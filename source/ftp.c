// FTP server for PS4 and Linux.
// https://github.com/hippie68/ps4-ftp

#include "ftp.h"

extern _Atomic int run; // The server keeps running as long as the value is 1.

#ifdef PS4
static _Atomic int decrypt; // The server decrypts SELF files if the value is 1.
#else
extern int read_only_mode; // Write commands are disabled if the value is 1.
#endif

static struct in_addr server_ip;         // Server's IPv4 address in binary form
static unsigned short server_port;       // Server's port
static pthread_t server_thid;            // Server's thread ID
static _Atomic int server_sockfd;        // Server's socket file descriptor
static struct client_info *client_list;  // Linked list used for SHUTDOWN
static pthread_mutex_t client_list_mtx;  // Linked list's lock
static struct ftp_command *ftp_commands; // Points to available FTP commands

/// Debug functions ------------------------------------------------------------

#if (defined(PS4) && defined(DEBUG_PS4)) || (!defined(PS4) && defined(DEBUG))
// Sends a debug message containing a return value's error information.
// In some cases, return values for PS4 functions are < 0 instead of exactly -1.
#define debug_retval(ret_val)                                         \
    do {                                                              \
        debug_msg("Line %d: Return value: %d, errno: %d (\"%s\").\n", \
            __LINE__, ret_val, errno, strerror(errno));               \
        errno = 0;                                                    \
    } while (0)

// Same, but can be wrapped around functions of return type int to debug
// non-zero return values. Useful if the return value does not need to be saved.
#define debug_func(ret_val)                                                    \
    do {                                                                       \
        if (ret_val) {                                                         \
            debug_msg("Line %d: " #ret_val ": Return value: %d, errno:"        \
                " %d (\"%s\").\n", __LINE__, ret_val, errno, strerror(errno)); \
            errno = 0;                                                         \
        }                                                                      \
    } while (0)
#else
#define debug_retval(x)
#define debug_func(x) x
#endif

/// Reimplementation of missing functions --------------------------------------

// PS4 is missing tolower(), strcasecmp(), and strcasestr().
#ifdef PS4
static inline int tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        c += 32;
    return c;
}

static int strcasecmp(const char *s1, const char *s2)
{
    int c1, c2;

    do {
        c1 = tolower(*s1);
        c2 = tolower(*s2);
        if (c1 != c2)
            break;
    } while (s1++, *s2++);

    return c1 - c2;
}
#endif

static char *strcasestr(const char *haystack, const char *needle)
{
    if (*haystack == '\0' || *needle == '\0')
        return NULL;

    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);
    if (haystack_len < needle_len)
        return NULL;
    size_t diff_len = haystack_len - needle_len;

    do {
        if (tolower(*haystack) == tolower(*needle)) {
            const char *a = haystack;
            const char *b = needle;
            do {
                ++a;
                ++b;
                if (*b == '\0')
                    return (char *) haystack;
            } while (tolower(*a) == tolower(*b));
        }
        ++haystack;
    } while (diff_len-- > 0);

    return NULL;
}

/// Message-sending functions --------------------------------------------------

// Sends a control message string to a connected client.
// Only complete messages, ending with CRLF, should be sent.
#define send_ctrl_msg(client, str)                                       \
    do {                                                                 \
        send(client->ctrl_sockfd, str, strlen(str), MSG_NOSIGNAL);       \
        log_msg("%s@%d < \"%.*s\"\n", client->ipv4, client->ctrl_sockfd, \
            (int) strlen(str) - 2, str);                                 \
    } while (0)

// Sends a formatted control message string to a connected client.
#define sendf_ctrl_msg(client, fmt, ...)                \
    do {                                                \
        char msg[CMD_LINE_BUF_SIZE];                    \
        snprintf(msg, sizeof(msg), fmt, ##__VA_ARGS__); \
        send_ctrl_msg(client, msg);                     \
    } while (0)

// Same as sendf_ctrl_msg(), but uses the data connection.
#define sendf_data_msg(client, fmt, ...)                \
    do {                                                \
        char msg[CMD_LINE_BUF_SIZE];                    \
        snprintf(msg, sizeof(msg), fmt, ##__VA_ARGS__); \
        send_data_msg(client, msg);                     \
    } while (0)

/// Functions shared by FTP commands -------------------------------------------

// Checks if a file or path exists on the FTP server.
// Used in FTP commands LIST and RNFR.
static int ftp_file_exists(const char *path)
{
    struct stat s;
    return (stat(path, &s) >= 0);
}

// Opens a client's data connection, returning < 0 on error.
// Used in FTP commands RETR and STOR.
static int open_data_connection(struct client_info *client)
{
    int ret;

    if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE)
        ret = connect(client->data_sockfd, (struct sockaddr *)
            &client->data_sockaddr, sizeof(client->data_sockaddr));
    else
        ret = client->pasv_sockfd = accept(client->data_sockfd, NULL, NULL);

    if (ret < 0) {
        debug_retval(ret);
    }

    return ret;
}

// Closes a client's data connection.
// Used in FTP commands LIST, NLST, RETR, and STOR.
static void close_data_connection(struct client_info *client)
{
    if (client->data_con_type == FTP_DATA_CONNECTION_NONE)
        return;

    debug_func(SOCKETCLOSE(client->data_sockfd));
    if (client->data_con_type == FTP_DATA_CONNECTION_PASSIVE)
        debug_func(SOCKETCLOSE(client->pasv_sockfd));

    client->data_con_type = FTP_DATA_CONNECTION_NONE;
}

// Sends a string via a client's data connection.
// Used in FTP commands LIST and NLST.
static inline void send_data_msg(struct client_info *client, char *str)
{
    if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE)
        send(client->data_sockfd, str, strlen(str), MSG_NOSIGNAL);
    else
        send(client->pasv_sockfd, str, strlen(str), MSG_NOSIGNAL);
}

// Causes a client's thread to exit.
// Used in FTP command QUIT and function client_list_terminate().
static void client_thread_exit(struct client_info *client)
{
    // Abort any open data connections.
    if (client->data_con_type != FTP_DATA_CONNECTION_NONE) {
#ifdef PS4
        debug_func(sceNetSocketAbort(client->data_sockfd,
            SCE_NET_SOCKET_ABORT_FLAG_RCV_PRESERVATION
            | SCE_NET_SOCKET_ABORT_FLAG_SND_PRESERVATION));
#else
        debug_func(shutdown(client->data_sockfd, SHUT_RDWR));
#endif
        if (client->data_con_type == FTP_DATA_CONNECTION_PASSIVE) {
#ifdef PS4
            debug_func(sceNetSocketAbort(client->pasv_sockfd,
                SCE_NET_SOCKET_ABORT_FLAG_RCV_PRESERVATION
                | SCE_NET_SOCKET_ABORT_FLAG_SND_PRESERVATION));
#else
            debug_func(shutdown(client->pasv_sockfd, SHUT_RDWR));
#endif
        }
    }

    // Unblock the client thread's blocking accept() to make the thread exit.
#ifdef PS4
    debug_func(sceNetSocketAbort(client->ctrl_sockfd,
        SCE_NET_SOCKET_ABORT_FLAG_RCV_PRESERVATION));
#else
    debug_func(shutdown(client->ctrl_sockfd, SHUT_RD));
#endif
}

// Generates an absolute FTP path string from the current working directory and
// an absolute or relative pathname and stores it in the provided buffer. The
// buffer should be of size PATH_MAX in order not to get truncated.
// Used in FTP commands APPE, CWD, DELE, LIST, MDTM, MLSD, MLST, MKD, NLST,
// RETR, RMD, RNFR, RNTO, "SITE CHMOD", SIZE, and STOR.
static int gen_ftp_path(char *buf, size_t buf_size, struct client_info *client,
    char *pathname)
{
    int n;

    if (pathname == NULL)
        n = snprintf(buf, buf_size, "%s", client->cur_path);
    else if (pathname[0] == '/') // Path is already absolute.
        n = snprintf(buf, buf_size, "%s", pathname);
    else // Concatenate both paths.
        n = snprintf(buf, buf_size, "%s%s%s", client->cur_path,
            client->cur_path[1] == '\0' ? "" : "/", pathname);

    if (n >= 0 && (unsigned int) n + 1 > buf_size) { // FTP path got truncated.
        debug_msg("Generated path larger than buffer.\n");
        return -1;
    } else {
        return 0;
    }
}

// Copies a source string to a buffer, inserting additional double quote
// characters, as required by the FTP standard. The buffer must be large enough
// to hold the additional characters, e.g. strlen(source) * 2 + 1.
// Used in FTP commands MKD and PWD.
static int gen_quoted_path(char *buf, int buf_size, char *source)
{
    if (source == NULL) {
        debug_msg("String is NULL.\n");
        return -1;
    }

    int len = strlen(source);
    int i = 0, buf_i = 0;
    for (; i < len && buf_i < buf_size - 1; i++, buf_i++) {
        buf[buf_i] = source[i];
        if (source[i] == '"')
            buf[++buf_i] = '"';
    }

    if (buf_i > buf_size - 1) {
        debug_msg("Buffer too small.\n");
        return -1;
    }

    buf[buf_i] = '\0';
    return 0;
}

// Sends a single file's facts via a client's data/control connection.
// Used in FTP commands MLSD and MLST.
// *path: the file's absolute path
static int send_facts(struct client_info *client, char *path, char *filename,
    _Bool use_data_con)
{
    struct stat statbuf;
    if (stat(path, &statbuf) < 0)
        return -1;

    char *type;
    if (client->facts.type) {
        if (S_ISDIR(statbuf.st_mode)) {
            if (filename[0] == '.' && filename[1] == '\0')
                type = "type=cdir;";
            else if (filename[0] == '.' && filename[1] == '.'
                && filename[2] == '\0')
                type = "type=pdir;";
            else
                type = "type=dir;";
        } else {
            type = "type=file;";
        }
    } else {
        type = "";
    }

    char size[26];
    if (client->facts.size)
        snprintf(size, sizeof(size), "size=%ld;", statbuf.st_size);
    else
        size[0] = '\0';

    char unique[42];
    if (client->facts.unique)
        snprintf(unique, sizeof(unique), "unique=%lx-%lx;", statbuf.st_dev,
            statbuf.st_ino);
    else
        unique[0] = '\0';

    char modify[23];
    if (client->facts.modify) {
        struct tm t;
        if (gmtime_r(&statbuf.st_mtim.tv_sec, &t) == NULL)
            return -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(modify, sizeof(modify), "modify=%d%02d%02d%02d%02d%02d;",
            1900 + t.tm_year, 1 + t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min,
            t.tm_sec);
#pragma GCC diagnostic pop
    } else {
        modify[0] = '\0';
    }

    char owner[20];
    if (client->facts.unix_owner)
        snprintf(owner, sizeof(owner), "unix.owner=%d;", statbuf.st_uid);
    else
        owner[0] = '\0';

    char group[20];
    if (client->facts.unix_group)
        snprintf(group, sizeof(group), "unix.group=%d;", statbuf.st_gid);
    else
        group[0] = '\0';

    char mode[16];
    if (client->facts.unix_mode) {
        int perm = statbuf.st_mode & (01111 | 02222 | 04444);
        snprintf(mode, sizeof(mode), "unix.mode=%04o;", perm);
    } else {
        mode[0] = '\0';
    }

    if (use_data_con)
        sendf_data_msg(client, "%s%s%s%s%s%s%s %s" CRLF,
            type, size, unique, modify, owner, group, mode, filename);
    else
        sendf_ctrl_msg(client, " %s%s%s%s%s%s%s %s" CRLF, // Leading space req.
            type, size, unique, modify, owner, group, mode, filename);

    return 0;
}

// Sets a client's current directory to its parent directory.
// Used in FTP commands CWD and CDUP.
static int dir_up(struct client_info *client)
{
#ifdef PS4 // Does not have the function access().
    char *slash = strrchr(client->cur_path, '/');
    if (slash == NULL)
        return -1;

    if (slash == client->cur_path)
        strcpy(client->cur_path, "/");
    else
        *slash = '\0';

    return 0;
#else
    char temp_path[sizeof(client->cur_path)];
    strcpy(temp_path, client->cur_path);

    char *slash = strrchr(temp_path, '/');
    if (slash == NULL)
        return -1;

    if (slash == temp_path)
        strcpy(temp_path, "/");
    else
        *slash = '\0';

    // Check if directory is accessible.
    int ret;
    if ((ret = access(temp_path, R_OK)) < 0) {
        debug_retval(ret);
        return -1;
    }

    strcpy(client->cur_path, temp_path);
    return 0;
#endif
}

// Receives a file from the client and stores it on the server.
// Used in FTP commands APPE and STOR.
static void recv_file(struct client_info *client, const char *path)
{
    // Set file flags for open().
    int flags = O_CREAT | O_RDWR; // Create file if necessary, open in r/w mode.
    if (client->restore_point == -1)
        flags = flags | O_APPEND; // Append new data to the end of the file.
    else if (client->restore_point == 0)
        flags = flags | O_TRUNC;  // Reset the file to length 0.

    // Open local file, creating it if necessary.
    int fd;
    if ((fd = open(path, flags, ~client->umask & FILE_PERM)) < 0) {
        debug_retval(fd);
        send_ctrl_msg(client, RC_550);
        return;
    }

    // Apply restore point.
    if (client->restore_point > 0) {
        struct stat sb;
        int ret;
        if ((ret = fstat(fd, &sb)) < 0
            || client->restore_point > sb.st_size
            || (ret = ftruncate(fd, client->restore_point)) < 0
            || (ret = lseek(fd, 0, SEEK_END)) < 0)
        {
            debug_retval(ret);
            close(fd);
            send_ctrl_msg(client, RC_451);
            return;
        }
    }

    // Open data connection.
    send_ctrl_msg(client, RC_150);
    if (open_data_connection(client) < 0) {
        close(fd);
        send_ctrl_msg(client, RC_425);
        return;
    }

    // Receive remote file data and write it to local file.
    int sockfd;
    if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE)
        sockfd = client->data_sockfd;
    else
        sockfd = client->pasv_sockfd;
    unsigned char buffer[FILE_BUF_SIZE];
    int n_received;
    int n_written;
    while ((n_received = recv(sockfd, buffer, sizeof(buffer), 0)) > 0) {
        if ((n_written = write(fd, buffer, n_received)) != n_received) {
            debug_retval(n_written);
            close(fd);
            close_data_connection(client);
            send_ctrl_msg(client, RC_451);
            return;
        }
    }

    close(fd);
    close_data_connection(client);

    if (n_received == 0) { // Success.
        send_ctrl_msg(client, RC_226);
    } else {
        debug_retval(n_received);
        if (errno == 28)
            send_ctrl_msg(client, RC_452);
        else
            send_ctrl_msg(client, RC_426);
    }
}

#ifdef PS4
// Decrypts a SELF file and stores the decrypted file's path in a buffer.
// Used in FTP commands RETR and SIZE.
static int decrypt_temp(struct client_info *client, char *file_path, char *buf,
    size_t bufsize)
{
    char temp_path[bufsize];

    // Create a unique file name.
    int ret = snprintf(temp_path, bufsize, "/user/temp/ftp_temp_file_%d",
        client->ctrl_sockfd);
    if (ret < 0 || (unsigned int) ret > bufsize -1) {
        debug_retval(ret);
        return -1;
    }
    while (file_exists(temp_path) && strlen(temp_path) + 1 < bufsize) {
        debug_msg("Temporary file \"%s\" already exists.\n", temp_path);
        strcat(temp_path, "_");
    }

    debug_msg("Decrypting file \"%s\", using temporary file \"%s\"...\n",
        file_path, temp_path);
    decrypt_and_dump_self(file_path, temp_path);
    strcpy(buf, temp_path);

    return 0;
}
#endif

/// FTP commands ---------------------------------------------------------------

// APPE (Append or create) "APPE <SP> <pathname> <CRLF>" -----------------------

static void cmd_APPE(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_553);
        return;
    }

    client->restore_point = -1; // Tell recv_file() to use the O_APPEND flag.
    recv_file(client, path);
}

// CDUP (Change to parent directory) "CDUP <CRLF>" -----------------------------

static void cmd_CDUP(struct client_info *client)
{
    if (dir_up(client))
        send_ctrl_msg(client, RC_550);
    else
        send_ctrl_msg(client, RC_200);
}

// CWD (Change working directory) "CWD <SP> <pathname <CRLF>" ------------------

static void cmd_CWD(struct client_info *client)
{
    if (strcmp(client->cmd_args, "..") == 0)
        dir_up(client);
    else if (strcmp(client->cmd_args, ".") == 0)
        return;

    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

#ifdef PS4
    if (ftp_file_exists(path)) {
#else
    if (access(path, R_OK) == 0) {
#endif
        strncpy(client->cur_path, path, sizeof(client->cur_path));
        send_ctrl_msg(client, RC_250);
    } else {
        send_ctrl_msg(client, RC_550);
    }
}

// DELE (Delete) "DELE <SP> <pathname> <CRLF>" ---------------------------------

static void cmd_DELE(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    int ret;
    if ((ret = unlink(path)) < 0) {
        debug_retval(ret);
        send_ctrl_msg(client, RC_550);
    } else {
        send_ctrl_msg(client, RC_250);
    }
}

// FEAT (Feature) "FEAT <CRLF>" ------------------------------------------------

static void cmd_FEAT(struct client_info *client)
{
    send_ctrl_msg(client, "211-Extensions:" CRLF);
    send_ctrl_msg(client, " MDTM" CRLF);
    sendf_ctrl_msg(client, " MLST type%s;size%s;unique%s;modify%s;"
        "unix.owner%s;unix.group%s;unix.mode%s;" CRLF,
        client->facts.type ? "*" : "",
        client->facts.size ? "*" : "",
        client->facts.unique ? "*" : "",
        client->facts.modify ? "*" : "",
        client->facts.unix_owner ? "*" : "",
        client->facts.unix_group ? "*" : "",
        client->facts.unix_mode ? "*" : "");
    send_ctrl_msg(client, " REST STREAM" CRLF);
    send_ctrl_msg(client, " SITE CHMOD" CRLF);
    send_ctrl_msg(client, " SITE UMASK" CRLF);
    send_ctrl_msg(client, " SIZE" CRLF);
    send_ctrl_msg(client, "211 END" CRLF);
}

// LIST (List) "LIST [<SP> <pathname>] <CRLF>" ---------------------------------

static int gen_list_format(char *out, int n, struct stat *st, char *file_name,
    char *link_name, int cur_year)
{
    static const char num_to_month[][4] = { "Jan", "Feb", "Mar", "Apr", "May",
        "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    struct tm file_tm;
    gmtime_r(&st->st_mtim.tv_sec, &file_tm);
    char yt[6];
    if (file_tm.tm_year == cur_year)
        snprintf(yt, sizeof(yt), "%02d:%02d", file_tm.tm_hour, file_tm.tm_min);
    else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(yt, sizeof(yt), "%d", 1900 + cur_year);
#pragma GCC diagnostic pop

#define LIST_FMT "%c%c%c%c%c%c%c%c%c%c %ld %d %d %ld %s %2d %s %s"
#define LIST_ARGS                                                  \
    S_ISREG(st->st_mode) ? '-' : S_ISDIR(st->st_mode) ? 'd'        \
        : S_ISLNK(st->st_mode) ? 'l' : S_ISBLK(st->st_mode) ? 'b'  \
        : S_ISCHR(st->st_mode) ? 'c' : S_ISFIFO(st->st_mode) ? 'p' \
        : S_ISSOCK(st->st_mode) ? 's' : '?',                       \
    st->st_mode & 0400 ? 'r' : '-',                                \
    st->st_mode & 0200 ? 'w' : '-',                                \
    st->st_mode & 0100 ? (st->st_mode & 04000 ? 's' : 'x')         \
        : st->st_mode & 04000 ? 'S' : '-',                         \
    st->st_mode & 040 ? 'r' : '-',                                 \
    st->st_mode & 020 ? 'w' : '-',                                 \
    st->st_mode & 010 ? (st->st_mode & 02000 ? 's' : 'x')          \
        : st->st_mode & 02000 ? 'S' : '-',                         \
    st->st_mode & 04 ? 'r' : '-',                                  \
    st->st_mode & 02 ? 'w' : '-',                                  \
    st->st_mode & 01 ? (st->st_mode & 01000 ? 't' : 'x')           \
        : st->st_mode & 01000 ? 'T' : '-',                         \
    st->st_nlink,                                                  \
    st->st_uid,                                                    \
    st->st_gid,                                                    \
    st->st_size,                                                   \
    num_to_month[file_tm.tm_mon],                                  \
    file_tm.tm_mday,                                               \
    yt,                                                            \
    file_name

    if (link_name)
        return snprintf(out, n, LIST_FMT " -> %s" CRLF, LIST_ARGS, link_name);
    else
        return snprintf(out, n, LIST_FMT CRLF, LIST_ARGS);

#undef LIST_FMT
#undef LIST_ARGS
}

// Sends list information about a file or directory via the data connection.
static void send_list_item(struct client_info *client, char *path,
    char *file_name, int cur_year)
{
    char buffer[CMD_LINE_BUF_SIZE];
    struct stat st;

    int ret = stat(path, &st);
    if (ret < 0) {
        debug_retval(ret);
        return;
    }

    // Get symbolic link.
    char link_path[PATH_MAX];
    link_path[0] = '\0';
    if (S_ISLNK(st.st_mode)) {
        ssize_t n = readlink(path, link_path, sizeof(link_path));
        if (n > 0)
            link_path[n] = '\0';
        else {
            debug_retval((int) n);
        }
    }

    gen_list_format(buffer, sizeof(buffer), &st, file_name,
        link_path[0] ? link_path : NULL, cur_year);

    send_data_msg(client, buffer);
}

static void send_list(struct client_info *client, char *path)
{
    DIR *dfd;
    struct dirent *dp;
    struct stat st;

    // Check if path is a directory.
    int is_dir;
    int ret = stat(path, &st);
    if (ret < 0) {
        debug_retval(ret);
        return;
    }
    is_dir = S_ISDIR(st.st_mode);

    if (is_dir) {
        // Open directory.
        if ((dfd = opendir(path)) == NULL) {
            send_ctrl_msg(client, RC_550);
            return;
        }
    }

    // Open data connection.
    send_ctrl_msg(client, RC_150);
    if (open_data_connection(client) < 0) {
        if (is_dir)
            closedir(dfd);
        send_ctrl_msg(client, RC_425);
        return;
    }

    // Get current year.
    time_t cur_time;
    struct tm cur_tm;
    time(&cur_time);
    gmtime_r(&cur_time, &cur_tm);

    if (is_dir) { // Send directory content list.
        while ((dp = readdir(dfd)) != NULL) {
            char file_path[PATH_MAX];
            snprintf(file_path, sizeof(file_path), "%s/%s", path, dp->d_name);
            send_list_item(client, file_path, dp->d_name, cur_tm.tm_year);
        }
        closedir(dfd);
    } else { // Send single-file list.
        send_list_item(client, path, path, cur_tm.tm_year);
    }

    send_ctrl_msg(client, RC_226);
    close_data_connection(client);
}

static void cmd_LIST(struct client_info *client)
{
    if (client->cmd_args) {
        char path[PATH_MAX];
        if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
            send_ctrl_msg(client, RC_550);
            return;
        }

        if (ftp_file_exists(path))
            send_list(client, path);
        else if (strcmp("-a", client->cmd_args) == 0) // "Show all files".
            send_list(client, client->cur_path);
        else
            send_ctrl_msg(client, RC_550);
    } else {
        send_list(client, client->cur_path);
    }
}

// MDTM (Modification time) "MDTM <SP> <pathname> <CRLF>" ----------------------

static void cmd_MDTM(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    struct tm t;
    if (gmtime_r(&st.st_mtim.tv_sec, &t) == NULL) {
        send_ctrl_msg(client, RC_451);
        return;
    }

    sendf_ctrl_msg(client, "213 %d%02d%02d%02d%02d%02d" CRLF, 1900 + t.tm_year,
        1 + t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
}

// MKD (Make directory) "MKD <SP> <pathname> <CRLF>" ---------------------------

static void cmd_MKD(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_553);
        return;
    }

    int ret = mkdir(path, ~client->umask & DIR_PERM);
    if (ret < 0) {
        debug_retval(ret);
        send_ctrl_msg(client, RC_550);
    } else {
        char quoted_path[strlen(path) * 2 + 1];
        if (gen_quoted_path(quoted_path, sizeof(quoted_path), path) < 0) {
            send_ctrl_msg(client, RC_550);
            return;
        }
        sendf_ctrl_msg(client, "257 \"%s\" created." CRLF, quoted_path);
    }
}

// MLSD (Machine-readable list directory) "MLSD [<SP> <pathname>] CRLF" --------

static void cmd_MLSD(struct client_info *client)
{
    struct dirent *dp;
    DIR *dfd;
    char dir_path[PATH_MAX];
    char *dir_p;

    if (client->cmd_args) {
        if (gen_ftp_path(dir_path, sizeof(dir_path), client, client->cmd_args)
            || !ftp_file_exists(dir_path)) {
            send_ctrl_msg(client, RC_550);
            return;
        }
        dir_p = dir_path;
    } else {
        dir_p = client->cur_path;
    }

    if ((dfd = opendir(dir_p)) == NULL) {
        send_ctrl_msg(client, "501 Argument is not a directory." CRLF);
        return;
    }

    // Open data connection.
    send_ctrl_msg(client, RC_150);
    if (open_data_connection(client) < 0) {
        send_ctrl_msg(client, RC_425);
        closedir(dfd);
        return;
    }

    // Send directory items.
    char path[PATH_MAX + 1]; // +1 because dir can be '/'.
    while ((dp = readdir(dfd)) != NULL) {
        if (snprintf(path, sizeof(path), "%s/%s", dir_p, dp->d_name) > PATH_MAX
            || send_facts(client, path, dp->d_name, 1)) {
            send_ctrl_msg(client, RC_451);
            closedir(dfd);
            close_data_connection(client);
            return;
        }
    }

    send_ctrl_msg(client, RC_226);
    closedir(dfd);
    close_data_connection(client);
}

// MLST (Machine-readable list) "MLST [<SP> <pathname>] CRLF" ------------------

static void cmd_MLST(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)
        || !ftp_file_exists(path)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    sendf_ctrl_msg(client, "250-Listing %s" CRLF,
        client->cmd_args ? client->cmd_args : client->cur_path);
    if (send_facts(client, path, client->cmd_args ? client->cmd_args
        : client->cur_path, 0))
        send_ctrl_msg(client, RC_451);
    else
        send_ctrl_msg(client, RC_250);
}

// MODE (Transfer mode) "MODE <SP> <structure-code> <CRLF>" --------------------

static void cmd_MODE(struct client_info *client)
{
    if (client->cmd_args[0] == 'S' || client->cmd_args[0] == 's')
        send_ctrl_msg(client, RC_200);
    else
        send_ctrl_msg(client, RC_504);
}

// NLST (Name list) "NLST [<SP> <pathname>] <CRLF>" ----------------------------

#ifdef PS4
#define str_swap(a, b) { \
    char *temp = a;      \
    a = b;               \
    b = temp;            \
}

void dumbsort(char **arr, ssize_t n)
{
    for (ssize_t i = 0; i < n - 1; i++) {
        ssize_t lowest = i;
        for (ssize_t j = i; j < n; j++)
            if (strcasecmp(arr[j], arr[lowest]) < 0)
                lowest = j;
        str_swap(arr[i], arr[lowest]);
    }
}
#else
static int qsort_strcasecmp(const void *a, const void *b)
{
    return strcasecmp(*(const char **) a, *(const char **) b);
}
#endif

static void cmd_NLST(struct client_info *client)
{
    struct dirent *dp;
    DIR *dfd;
    char dir_path[PATH_MAX];
    char *dir_p;

    if (client->cmd_args) {
        if (gen_ftp_path(dir_path, sizeof(dir_path), client, client->cmd_args)
            || !ftp_file_exists(dir_path)) {
            send_ctrl_msg(client, RC_550);
            return;
        }
        dir_p = dir_path;
    } else {
        dir_p = client->cur_path;
    }

    if ((dfd = opendir(dir_p)) == NULL) {
        send_ctrl_msg(client, "501 Argument is not a directory." CRLF);
        return;
    }

    // Open data connection.
    send_ctrl_msg(client, RC_150);
    if (open_data_connection(client) < 0) {
        send_ctrl_msg(client, RC_425);
        return;
    }

    int flist_size = 0;
    char **flist = malloc(0);
    if (flist == NULL)
        goto out_of_memory;

    // Create file list.
    while ((dp = readdir(dfd)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;

        char *file_name = malloc(strlen(dp->d_name) + 3);
        if (file_name == NULL)
            goto out_of_memory;

        sprintf(file_name, "%s" CRLF, dp->d_name);
        flist = realloc(flist, sizeof(*flist) * ++flist_size);
        if (flist == NULL)
            goto out_of_memory;

        flist[flist_size -1] = file_name;
    }

    // Send sorted file list.
#ifdef PS4
    dumbsort(flist, flist_size);
#else
    qsort(flist, flist_size, sizeof(*flist), qsort_strcasecmp);
#endif
    for (int i = 0; i < flist_size; i++)
        send_data_msg(client, flist[i]);
    send_ctrl_msg(client, RC_226);
    close_data_connection(client);

    clean_up:
    for (int i = 0; i < flist_size; i++)
        free(flist[i]);
    free(flist);
    closedir(dfd);
    return;

    out_of_memory:
    debug_msg("Could not allocate memory.\n");
    close_data_connection(client);
    send_ctrl_msg(client, RC_451);
    goto clean_up;
}

// NOOP (No operation) "NOOP <CRLF>" -------------------------------------------

static void cmd_NOOP(struct client_info *client)
{
    send_ctrl_msg(client, RC_200);
}

// OPTS "OPTS" <SP> <subcommand> <CRLF> ----------------------------------------

// "MLST" [<SP> factname";"[factname";"...]] <CRLF>
static void cmd_OPTS_MLST(struct client_info *client, char *subcmd_args)
{
    client->facts = (struct facts) { 0 }; // Disable all facts.

    char reply[CMD_LINE_BUF_SIZE];
    reply[0] = '\0';

    if (subcmd_args == NULL)
        goto done;
    else
        subcmd_args++;

    if (strcasestr(subcmd_args, "type;")) {
        client->facts.type = 1;
        strcat(reply, "type;");
    }
    if (strcasestr(subcmd_args, "size;")) {
        client->facts.size = 1;
        strcat(reply, "size;");
    }
    if (strcasestr(subcmd_args, "unique;")) {
        client->facts.unique = 1;
        strcat(reply, "unique;");
    }
    if (strcasestr(subcmd_args, "modify;")) {
        client->facts.modify = 1;
        strcat(reply, "modify;");
    }
    if (strcasestr(subcmd_args, "unix.owner;")) {
        client->facts.unix_owner = 1;
        strcat(reply, "unix.owner;");
    }
    if (strcasestr(subcmd_args, "unix.group;")) {
        client->facts.unix_group = 1;
        strcat(reply, "unix.group;");
    }
    if (strcasestr(subcmd_args, "unix.mode;")) {
        client->facts.unix_mode = 1;
        strcat(reply, "unix.mode;");
    }

    done:
    sendf_ctrl_msg(client, "200 MLST OPTS %s" CRLF, reply);
}

static void cmd_OPTS(struct client_info *client)
{
    if (client->cmd_args == NULL) {
        send_ctrl_msg(client, RC_501);
        return;
    }

    if (strstr(client->cmd_args, "MLST") == client->cmd_args)
        cmd_OPTS_MLST(client, strchr(client->cmd_args, ' '));
    else
        send_ctrl_msg(client, RC_504);
}

// PASS (Password) "PASS <SP> <password> <CRLF>" -------------------------------

static void cmd_PASS(struct client_info *client)
{
    send_ctrl_msg(client, RC_202);
}

// PASV (Passive) "PASV <CRLF>" ------------------------------------------------

static void cmd_PASV(struct client_info *client)
{
    close_data_connection(client); // Drop any connections already made.

    if ((client->data_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        send_ctrl_msg(client, RC_451);
        return;
    }

    int ret;
    socklen_t socklen = sizeof(struct sockaddr_in);

    // To ensure the PASV IP is reachable, use the server IP the client uses for
    // its control connection.
    if ((ret = getsockname(client->ctrl_sockfd,
        (struct sockaddr *) &client->data_sockaddr, &socklen)) < 0)
        goto error;
    client->data_sockaddr.sin_port = htons(0); // But we need a different port.

    if ((ret = bind(client->data_sockfd, (struct sockaddr *)
        &client->data_sockaddr, sizeof(client->data_sockaddr))) < 0)
        goto error;

    if ((ret = listen(client->data_sockfd, 128)) < 0)
        goto error;

    struct sockaddr_in pasv_addr;
    if ((ret = getsockname(client->data_sockfd, (struct sockaddr *) &pasv_addr,
        &socklen)) < 0)
        goto error;

    client->data_con_type = FTP_DATA_CONNECTION_PASSIVE;

    char reply[CMD_LINE_BUF_SIZE];
    snprintf(reply, sizeof(reply),
        "227 Entering Passive Mode (%hhu,%hhu,%hhu,%hhu,%hhu,%hhu)." CRLF,
        (pasv_addr.sin_addr.s_addr >> 0) & 0xFF,
        (pasv_addr.sin_addr.s_addr >> 8) & 0xFF,
        (pasv_addr.sin_addr.s_addr >> 16) & 0xFF,
        (pasv_addr.sin_addr.s_addr >> 24) & 0xFF,
        (pasv_addr.sin_port >> 0) & 0xFF,
        (pasv_addr.sin_port >> 8) & 0xFF);
    send_ctrl_msg(client, reply);

    return;

error:
    debug_retval(ret);
    SOCKETCLOSE(client->data_sockfd);
    send_ctrl_msg(client, RC_451);
}

// PORT (Data port) "SP> <host-port> <CRLF>" -----------------------------------

static void cmd_PORT(struct client_info *client)
{
    unsigned char data_ip[4];
    unsigned char porthi = 0;
    unsigned char portlo = 0;
    unsigned short data_port;
    char ip_str[16];
    struct in_addr data_addr;
    int n;

    n = sscanf(client->cmd_args, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &data_ip[0],
        &data_ip[1], &data_ip[2], &data_ip[3], &porthi, &portlo);
    if (n != 6) {
        send_ctrl_msg(client, RC_501);
        return;
    }

    data_port = portlo + porthi * 256;
    sprintf(ip_str, "%d.%d.%d.%d", data_ip[0], data_ip[1], data_ip[2],
        data_ip[3]);
    inet_pton(AF_INET, ip_str, &data_addr);
    client->data_sockfd = socket(AF_INET, SOCK_STREAM, 0);

#ifdef PS4
    client->data_sockaddr.sin_len = sizeof(client->data_sockaddr);
#endif
    client->data_sockaddr.sin_family = AF_INET;
    client->data_sockaddr.sin_addr = data_addr;
    client->data_sockaddr.sin_port = htons(data_port);

    client->data_con_type = FTP_DATA_CONNECTION_ACTIVE;

    send_ctrl_msg(client, RC_200);
}

// PWD (Print working directory) "PWD <CRLF>" ----------------------------------

static void cmd_PWD(struct client_info *client)
{
    char path[strlen(client->cur_path) * 2 + 1];
    if (gen_quoted_path(path, sizeof(path), client->cur_path) < 0)
        send_ctrl_msg(client, RC_550);
    else
        sendf_ctrl_msg(client, "257 \"%s\" is the current directory." CRLF,
            path);
}

// QUIT (Close connection) "QUIT <CRLF>" ---------------------------------------

static void cmd_QUIT(struct client_info *client)
{
    send_ctrl_msg(client, RC_221);
    client_thread_exit(client);
}

// REST (Restart) "REST <SP> <marker> <CRLF> -----------------------------------

static void cmd_REST(struct client_info *client)
{
    long long marker;
    if (sscanf(client->cmd_args, "%lld", &marker) != 1) {
        send_ctrl_msg(client, RC_501);
        return;
    }

    client->restore_point = marker;
    sendf_ctrl_msg(client, "350 Resuming at %lld." CRLF, client->restore_point);
}

// RETR (Retreive) "RETR <SP> <pathname> <CRLF>" -------------------------------

// Sends a local file to a client.
static void send_file(struct client_info *client, const char *path)
{
    int fd, ret;

    // Open local file.
    if ((fd = open(path, O_RDONLY, 0)) < 0) {
        debug_retval(fd);
        send_ctrl_msg(client, RC_550);
        return;
    }

    // Skip to a previous REST command's offset.
    if (client->restore_point > 0
        && (ret = lseek(fd, client->restore_point, SEEK_SET)) < 0) {
        debug_retval(ret);
        send_ctrl_msg(client, RC_550);
        close(fd);
        return;
    }

    // Open data connection.
    send_ctrl_msg(client, RC_150);
    if (open_data_connection(client) < 0) {
        send_ctrl_msg(client, RC_425);
        close(fd);
        return;
    }

    // Send the file.
    int sockfd;
    if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE)
        sockfd = client->data_sockfd;
    else
        sockfd = client->pasv_sockfd;
#if defined(PS4) || defined(NON_LINUX)
    unsigned char buffer[FILE_BUF_SIZE];
    int n_read;
    while ((n_read = read(fd, buffer, FILE_BUF_SIZE)) > 0) {
        if (n_read != send(sockfd, buffer, n_read, MSG_NOSIGNAL)) {
            close(fd);
            close_data_connection(client);
            send_ctrl_msg(client, RC_426);
            return;
        }
    }

    close(fd);
    close_data_connection(client);

    if (n_read < 0) {
        debug_retval(n_read);
        send_ctrl_msg(client, RC_451);
        return;
    }
#else
    // The PS4 seems to have an old, slow version of FreeBSD's sendfile().
    // On Linux however, using sendfile() should be faster.
    struct stat sb;
    fstat(fd, &sb);
    off_t n_left = sb.st_size;
    ssize_t n_sent;

    signal(SIGPIPE, SIG_IGN);
    while ((n_sent = sendfile(sockfd, fd, NULL, n_left)) >= 0
        && n_sent < n_left)
        n_left -= n_sent;
    signal(SIGPIPE, SIG_DFL);

    close(fd);
    close_data_connection(client);

    if (n_sent < 0) {
        debug_retval((int) n_sent);
        send_ctrl_msg(client, RC_451);
        return;
    }
#endif

    send_ctrl_msg(client, RC_226);
}

// Sends a local file to a client, replacing newline (LF) characters with CRLF.
static void send_text_file(struct client_info *client, const char *path)
{
    int fd;

    // Open local file.
    if ((fd = open(path, O_RDONLY, 0)) < 0) {
        debug_retval(fd);
        send_ctrl_msg(client, RC_550);
        return;
    }

    // Open data connection.
    send_ctrl_msg(client, RC_150);
    if (open_data_connection(client) < 0) {
        send_ctrl_msg(client, RC_425);
        close(fd);
        return;
    }

    // Send the file.
    int sockfd;
    if (client->data_con_type == FTP_DATA_CONNECTION_ACTIVE)
        sockfd = client->data_sockfd;
    else
        sockfd = client->pasv_sockfd;
    unsigned char buffer[FILE_BUF_SIZE];
    int n_read;
    while ((n_read = read(fd, buffer, sizeof(buffer))) > 0) {
        int start = 0;
        int size, ret;

        // Send buffer line by line.
        for (int i = 0; i < n_read; i++) {
            if (buffer[i] == '\n') {
                buffer[i] = '\r';
                size = i + 1 - start;
                if ((ret = send(sockfd, buffer + start, size, MSG_NOSIGNAL))
                    != size) {
                    debug_retval(ret);
                    close(fd);
                    close_data_connection(client);
                    send_ctrl_msg(client, RC_426);
                    return;
                }
                buffer[i] = '\n';
                start = i;
            }
        }

        // Send remaining buffer.
        size = n_read - start;
        if ((ret = send(sockfd, buffer + start, size, MSG_NOSIGNAL))
            != size) {
            debug_retval(ret);
            close(fd);
            close_data_connection(client);
            send_ctrl_msg(client, RC_426);
            return;
        }
    }

    close(fd);
    close_data_connection(client);

    if (n_read < 0) {
        debug_retval(n_read);
        send_ctrl_msg(client, RC_451);
        return;
    }

    send_ctrl_msg(client, RC_226);
}

static void cmd_RETR(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

#ifdef PS4
    if (decrypt && is_self(path)) {
        char temp_path[PATH_MAX];
        if (decrypt_temp(client, path, temp_path, sizeof(temp_path))) {
            send_ctrl_msg(client, RC_451);
            return;
        }
        send_file(client, temp_path);
        debug_func(unlink(temp_path));
    } else
#endif

    if (client->binary_flag)
        send_file(client, path);
    else
        send_text_file(client, path);
}

// RMD (Remove directory) "RMD <SP> <pathname> <CRLF>" -------------------------

static void delete_dir(struct client_info *client, const char *path)
{
    if (rmdir(path) >= 0)
        send_ctrl_msg(client, RC_250);
    else if (errno == 66) // ENOTEMPTY
        send_ctrl_msg(client, "550 Directory not empty." CRLF);
    else
        send_ctrl_msg(client, RC_550);
}

static void cmd_RMD(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    delete_dir(client, path);
}

// RNFR (Rename from) "RNFR <SP> <pathname> <CRLF>" ----------------------------

static void cmd_RNFR(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    if (!ftp_file_exists(path)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    strcpy(client->rename_path, path);
    send_ctrl_msg(client, RC_350);
}

// RNTO (Rename to) "RNTO <SP> <pathname> <CRLF>" ------------------------------

static void cmd_RNTO(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_553);
        return;
    }

    int ret;
    if ((ret = rename(client->rename_path, path)) < 0) {
        debug_retval(ret);
        send_ctrl_msg(client, RC_550);
    } else {
        send_ctrl_msg(client, RC_250);
    }
}

// SIZE (Size of file) "SIZE <SP> <pathname> <CRLF>" ---------------------------

static void cmd_SIZE(struct client_info *client)
{
    struct stat s;

    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    int ret;
    if ((ret = stat(path, &s)) < 0) {
        debug_retval(ret);
        send_ctrl_msg(client, RC_550);
        return;
    }

#ifdef PS4
    // If file is a SELF, decrypt it to retrieve the correct file size.
    if (decrypt && is_self(path)) {
        char temp_path[PATH_MAX];
        if (decrypt_temp(client, path, temp_path, sizeof(temp_path))) {
            send_ctrl_msg(client, RC_451);
            return;
        }
        debug_func(stat(temp_path, &s));
        debug_func(unlink(temp_path));
    }
#endif

    sendf_ctrl_msg(client, "213 %ld" CRLF, s.st_size);
}

// STRU (File structure) "STRU <SP> <structure-code> <CRLF>" -------------------

static void cmd_STRU(struct client_info *client)
{
    if (client->cmd_args[0] == 'F' || client->cmd_args[0] == 'f')
        send_ctrl_msg(client, RC_200);
    else
        send_ctrl_msg(client, RC_504);
}

// STOR (Store) "STOR <SP> <pathname> <CRLF>" ----------------------------------

static void cmd_STOR(struct client_info *client)
{
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, client->cmd_args)) {
        send_ctrl_msg(client, RC_553);
        return;
    }

    recv_file(client, path);
}

// SYST (System) "SYST <CRLF>" -------------------------------------------------

static void cmd_SYST(struct client_info *client)
{
    send_ctrl_msg(client, "215 UNIX Type: L8" CRLF);
}

// TYPE (Representation type) "TYPE <SP> <type-code> <CRLF>" -------------------

static void cmd_TYPE(struct client_info *client)
{
    switch (strlen(client->cmd_args)) {
        case 1:
            switch (client->cmd_args[0]) {
                case 'a':
                case 'A':
                    client->binary_flag = 0;
                    break;
                case 'i':
                case 'I':
                    client->binary_flag = 1;
                    break;
                default:
                    send_ctrl_msg(client, RC_504);
                    return;
            }
            break;
        case 3:
            if (strcasecmp(client->cmd_args, "a n") == 0) {
                client->binary_flag = 0;
            } else if (strcasecmp(client->cmd_args, "l 8") == 0) {
                client->binary_flag = 1;
            } else {
                send_ctrl_msg(client, RC_504);
                return;
            }
            break;
        default:
            send_ctrl_msg(client, RC_504);
            return;
    }

    send_ctrl_msg(client, RC_200);
}

// USER (User name) "USER <SP> <username> <CRLF>" ------------------------------

static void cmd_USER(struct client_info *client)
{
    send_ctrl_msg(client, RC_230);
}

// Custom SITE commands (not part of the FTP standard, but commonly used) ------

// Converts a string into a file mode, returning -1 on error.
// Used in FTP commands "SITE CHMOD" and "SITE UMASK".
static long string_to_mode(char *str)
{
    if (str == NULL || strlen(str) > 4)
        return -1;

    char modebuf[6] = "0";
    strncat(modebuf, str, 4);
    long mode = strtol(modebuf, NULL, 8);
    if (mode < 0 || mode > 07777)
        return -1;

    return mode;
}

// "SITE CHMOD <SP> <mode> <SP> <filename> <CRLF>"
static void cmd_SITE_CHMOD(struct client_info *client, char *args)
{
    if (!args) {
        send_ctrl_msg(client, RC_501);
        return;
    }

    char *mode_string = args;
    char *filename = strchr(args, ' ');
    if (!filename) {
        send_ctrl_msg(client, RC_501);
        return;
    }
    *filename++ = '\0';

    // Check if argument is a valid mode number.
    long mode = string_to_mode(mode_string);
    if (mode == -1) {
        send_ctrl_msg(client, RC_501);
        return;
    }

    // Set mode.
    char path[PATH_MAX];
    if (gen_ftp_path(path, sizeof(path), client, filename)) {
        send_ctrl_msg(client, RC_550);
        return;
    }
    if (chmod(path, mode) != 0)
        send_ctrl_msg(client, RC_451);
    else
        send_ctrl_msg(client, RC_250);
}

// "SITE UMASK <SP> <mask> <CRLF>"
static void cmd_SITE_UMASK(struct client_info *client, char *args)
{
    long mode;

    if (!args || (mode = string_to_mode(args)) == -1) {
        send_ctrl_msg(client, RC_501);
        return;
    }

    client->umask = mode;
    send_ctrl_msg(client, RC_200);
}

// Launches SITE commands ("SITE COMMAND [<SP> <parameters>]").
static void cmd_SITE(struct client_info *client)
{
    char *command = client->cmd_args;
    char *args = strchr(client->cmd_args, ' ');
    if (args)
        *args++ = '\0';

    if (strcasecmp(command, "CHMOD") == 0)
        cmd_SITE_CHMOD(client, args);
    else if (strcasecmp(command, "UMASK") == 0)
        cmd_SITE_UMASK(client, args);
    else
        send_ctrl_msg(client, RC_504);
}

// Custom FTP commands (not part of the FTP standard) --------------------------

#ifdef PS4
// Toggles server-side decryption of SELF files.
static void cmd_DECRYPT(struct client_info *client)
{
    if (decrypt == 0) {
        send_ctrl_msg(client, "200 SELF decryption enabled." CRLF);
        decrypt = 1;
    } else {
        send_ctrl_msg(client, "200 SELF decryption disabled." CRLF);
        decrypt = 0;
    }
}

// Obsolete, kept for compatibility with older scripts.
static void cmd_KILL(struct client_info *client)
{
    send_ctrl_msg(client, RC_202);
}

// Mounts the proc filesystem.
static void cmd_MTPROC(struct client_info *client)
{
    int result = mkdir("/mnt/proc", 0777);
    if (result >= 0 || (*__error()) == 17) {
        result = mount("procfs", "/mnt/proc", 0, NULL);
        if (result >= 0) {
            send_ctrl_msg(client, RC_200);
            return;
        } else {
            send_ctrl_msg(client, "550 Failed to mount procfs." CRLF);
        }
    } else {
        send_ctrl_msg(client, "550 Failed to create /mnt/proc." CRLF);
    }

    send_ctrl_msg(client, RC_550);
}

// Mounts read-only system partitions with read-write access.
static void cmd_MTRW(struct client_info *client)
{
    if (mount_large_fs("/dev/md0", "/", "exfatfs", "511", MNT_UPDATE) < 0
        || (mount_large_fs("/dev/da0x0.crypt", "/preinst", "exfatfs", "511",
            MNT_UPDATE) < 0)
        || (mount_large_fs("/dev/da0x1.crypt", "/preinst2", "exfatfs", "511",
            MNT_UPDATE) < 0)
        || (mount_large_fs("/dev/da0x4.crypt", "/system", "exfatfs", "511",
            MNT_UPDATE) < 0)
        || (mount_large_fs("/dev/da0x5.crypt", "/system_ex", "exfatfs", "511",
            MNT_UPDATE) < 0)) {
        send_ctrl_msg(client, RC_550);
        return;
    }

    send_ctrl_msg(client, RC_200);
}
#endif

// Causes the FTP server to exit.
static void cmd_SHUTDOWN(struct client_info *client)
{
    send_ctrl_msg(client, "200 Shutting down..." CRLF);
    run = 0;
}

#ifndef PS4
// Dummy command for read-only mode, used in place of commands that would write.
static void cmd_BLOCKED(struct client_info *client)
{
    send_ctrl_msg(client, RC_502);
}
#endif

// -----------------------------------------------------------------------------

// Creates a list of commands that are available to FTP clients.
static int create_command_list(void)
{
    struct ftp_command command_list[] = {
        // Standard FTP commands:
        { "APPE", cmd_APPE, ARGS_REQUIRED },
        { "CDUP", cmd_CDUP, ARGS_NONE     },
        { "CWD",  cmd_CWD,  ARGS_REQUIRED },
        { "DELE", cmd_DELE, ARGS_REQUIRED },
        { "FEAT", cmd_FEAT, ARGS_NONE     },
        { "LIST", cmd_LIST, ARGS_OPTIONAL },
        { "MDTM", cmd_MDTM, ARGS_REQUIRED },
        { "MLSD", cmd_MLSD, ARGS_OPTIONAL },
        { "MLST", cmd_MLST, ARGS_OPTIONAL },
        { "MKD",  cmd_MKD,  ARGS_REQUIRED },
        { "MODE", cmd_MODE, ARGS_REQUIRED },
        { "NLST", cmd_NLST, ARGS_OPTIONAL },
        { "NOOP", cmd_NOOP, ARGS_NONE     },
        { "OPTS", cmd_OPTS, ARGS_REQUIRED },
        { "PASS", cmd_PASS, ARGS_REQUIRED },
        { "PASV", cmd_PASV, ARGS_NONE     },
        { "PORT", cmd_PORT, ARGS_REQUIRED },
        { "PWD",  cmd_PWD,  ARGS_NONE     },
        { "QUIT", cmd_QUIT, ARGS_NONE     },
        { "REST", cmd_REST, ARGS_REQUIRED },
        { "RETR", cmd_RETR, ARGS_REQUIRED },
        { "RMD",  cmd_RMD,  ARGS_REQUIRED },
        { "RNFR", cmd_RNFR, ARGS_REQUIRED },
        { "RNTO", cmd_RNTO, ARGS_REQUIRED },
        { "SIZE", cmd_SIZE, ARGS_REQUIRED },
        { "STOR", cmd_STOR, ARGS_REQUIRED },
        { "STRU", cmd_STRU, ARGS_REQUIRED },
        { "SYST", cmd_SYST, ARGS_NONE     },
        { "TYPE", cmd_TYPE, ARGS_REQUIRED },
        { "USER", cmd_USER, ARGS_REQUIRED },
        // Custom FTP commands:
#ifdef PS4
        { "DECRYPT", cmd_DECRYPT, ARGS_NONE },
        { "MTPROC",  cmd_MTPROC,  ARGS_NONE },
        { "MTRW",    cmd_MTRW,    ARGS_NONE },
        { "KILL",    cmd_KILL,    ARGS_NONE },
#endif
        { "SHUTDOWN", cmd_SHUTDOWN, ARGS_NONE     },
        { "SITE",     cmd_SITE,     ARGS_REQUIRED },
        { NULL } // Marks the end of the array.
    };

#ifndef PS4
    // Enforce read-only mode by replacing write commands with a dummy command.
    if (read_only_mode) {
        struct ftp_command *cmd = command_list;
        void (*write_commands[])(struct client_info *) = {
            cmd_APPE,
            cmd_DELE,
            cmd_MKD,
            cmd_RMD,
            cmd_RNFR,
            cmd_RNTO,
            cmd_SITE,
            cmd_STOR,
        };
        size_t n = sizeof(write_commands)
            / sizeof(void (*)(struct client_info *));
        while (cmd->name) {
            for (size_t i = 0; i < n; i++)
                if (cmd->function == write_commands[i])
                    cmd->function = cmd_BLOCKED;
            cmd++;
        }
        log_msg("Enabled read-only mode.\n");
    }
#endif

    size_t list_size = sizeof(command_list);
    ftp_commands = malloc(list_size);
    if (ftp_commands == NULL) {
        debug_msg("Could not allocate memory.\n");
        return -1;
    }
    memcpy(ftp_commands, command_list, list_size);

    return 0;
}

// Runs the function associated with a client's received FTP command line.
static void run_cmd(struct client_info *client)
{
    struct ftp_command *cmd = ftp_commands;
    while (cmd->name) {
        if (strcasecmp(client->cmd_line, cmd->name) == 0) {
            if (client->cmd_args) {
                if (cmd->args_flag == ARGS_NONE) {
                    send_ctrl_msg(client, RC_501);
                    return;
                }
            } else {
                if (cmd->args_flag == ARGS_REQUIRED) {
                    send_ctrl_msg(client, RC_501);
                    return;
                }
            }
            cmd->function(client);

            // Restore points are meant to be used only right after REST.
            if (cmd->function != cmd_REST)
                client->restore_point = 0;

            return;
        }
        cmd++;
    }

    send_ctrl_msg(client, RC_502);
}

/// Threads --------------------------------------------------------------------

// Adds a client thread to the thread list.
static void client_list_add(struct client_info *client)
{
    debug_func(pthread_mutex_lock(&client_list_mtx));

    if (client_list == NULL) { // List is empty.
        client_list = client;
        client->prev = NULL;
        client->next = NULL;
    } else {
        client->next = client_list;
        client->next->prev = client;
        client->prev = NULL;
        client_list = client;
    }

    debug_func(pthread_mutex_unlock(&client_list_mtx));
}

// Deletes a client from the client list.
static void client_list_delete(struct client_info *client)
{
    debug_func(pthread_mutex_lock(&client_list_mtx));

    if (client->prev)
        client->prev->next = client->next;
    if (client->next)
        client->next->prev = client->prev;
    if (client == client_list)
        client_list = client->next;

    debug_func(pthread_mutex_unlock(&client_list_mtx));
}

// Causes all client threads to exit.
// The server thread should have exited before calling this function.
static void client_list_terminate()
{
    // Loop until the client list is empty.
    while (1) {
        debug_func(pthread_mutex_lock(&client_list_mtx));

        struct client_info *client = client_list;
        if (client == NULL) {
            debug_func(pthread_mutex_unlock(&client_list_mtx));
            break;
        }

        // Cause all remaining client threads to try to exit.
        do {
            client_thread_exit(client);
            client = client->next;
        } while (client);

        // The exiting threads need access to the list to be able to exit.
        debug_func(pthread_mutex_unlock(&client_list_mtx));

        usleep(1000);
    }
    debug_func(pthread_mutex_destroy(&client_list_mtx));
}

static void set_socket_timeout(int socket, int seconds)
{
    struct timeval t = { .tv_sec = seconds };
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
}

// This function is used as a separate thread for each new client.
static void *client_thread(void *arg)
{
    debug_func(pthread_detach(pthread_self()));

    struct client_info *client = (struct client_info *) arg;
    log_msg("Client %s connects to socket %d.\n", client->ipv4,
        client->ctrl_sockfd);
    send_ctrl_msg(client, "220 FTP server " RELEASE_VERSION " by hippie68."
        CRLF);

    // Disconnect after a period of inactivity.
    set_socket_timeout(client->ctrl_sockfd, 300);

    while (1) {
        // Receive a command line string from the client.
        ssize_t n = recv(client->ctrl_sockfd, client->cmd_line,
            sizeof(client->cmd_line) - 1, 0);

        if (n > 0) {
            // Remove the string's "end-of-line" (CRLF aka \r\n).
            client->cmd_line[n] = '\0';
            char *cmd_end = strrchr(client->cmd_line, '\n');
            if (cmd_end) {
                *cmd_end = '\0';
                if (*--cmd_end == '\r') // Some FTP clients only use '\n'.
                    *cmd_end = '\0';
            } else {
                if (n == sizeof(client->cmd_line) - 1) {
                    debug_msg("Received command line too long.\n");
                } else {
                    debug_msg("Received command line not terminated.\n");
                }
                send_ctrl_msg(client, RC_500);
                break; // Kick client for sending garbage.
            }

            log_msg("%s@%d > \"%s\"\n", client->ipv4, client->ctrl_sockfd,
                client->cmd_line);

            // Isolate arguments.
            if ((client->cmd_args = strchr(client->cmd_line, ' '))) {
                *client->cmd_args = '\0';
                client->cmd_args++;
                if (*client->cmd_args == '\0')
                    client->cmd_args = NULL; // Treat empty-arg as no-arg.
            }

            run_cmd(client);
        } else if (n == 0) { // FTP client disconnected (PS4 and non-PS4), or
            break;           // fini() has been called (non-PS4).
        } else if (n < 0) {
#ifdef PS4
            if (n != (int) SCE_NET_ERROR_EINTR) { // Would happen on fini().
                debug_msg("Error %d in client %s@%d's thread.\n", n,
                    client->ipv4, client->ctrl_sockfd);
            }
#else
            debug_msg("Error in client %s@%d's thread: %s.\n", client->ipv4,
                client->ctrl_sockfd, strerror(errno));
#endif
            break;
        }
    }

    log_msg("Client %s@%d disconnects.\n", client->ipv4, client->ctrl_sockfd);

    // Clean up.
    client_list_delete(client);
    debug_func(SOCKETCLOSE(client->ctrl_sockfd));
    close_data_connection(client);
    debug_msg("Client %s@%d's thread exits.\n", client->ipv4,
        client->ctrl_sockfd);
    free(client);
    return NULL;
}

// Listens for new clients and starts new client threads.
static void *server_thread(void *arg)
{
    // Set up the FTP server's default directory.
    char *default_directory = (char *) arg;
    if (default_directory == NULL)
        default_directory = DEFAULT_PATH;

    // Create the FTP command list.
    if (create_command_list()) {
        run = 0;
        return NULL;
    }

#ifndef PS4
    // Get the process' file mode creation mask.
    mode_t current_mask = umask(0);
    umask(current_mask);
#endif

    // Create server socket.
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int option_value = 1;
    setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &option_value,
        sizeof(option_value));

    // Fill in the server's IPv4 socket address.
    struct sockaddr_in serveraddr;
#ifdef PS4
    serveraddr.sin_len = sizeof(serveraddr); // This member only exists on PS4.
#endif
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(server_port);

    // Bind the server's address to the socket.
    if (bind(server_sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr))
        < 0) {
        printf_notification("Port %u already in use", server_port);
        run = 0; // On error, trigger server shutdown.
        return NULL;
    }

    // Start listening.
    listen(server_sockfd, 128);

#if (defined(PS4) && defined(DEBUG_PS4)) || !defined(PS4)
    char ipv4[16];
    inet_ntop(AF_INET, &server_ip, ipv4, sizeof(ipv4));
    log_msg("Server thread is listening on %s, socket %d, port %d.\n", ipv4,
        server_sockfd, server_port);
#endif

    // Accept clients.
    while (1) {
        struct sockaddr_in clientaddr;
        int client_sockfd;
        socklen_t addrlen = sizeof(clientaddr);

        client_sockfd = accept(server_sockfd, (struct sockaddr *) &clientaddr,
            &addrlen);

        if (client_sockfd < 0) {
#ifdef PS4
            if (client_sockfd != -2143223548 /* SHUTDOWN command on PS4 */ ) {
#else
            if (errno != 22 /* SHUTDOWN command on non-PS4 */ ) {
#endif
                debug_retval(client_sockfd);
            }
            break;
        } else {
            // Allocate the new client struct (all values are set to 0).
            struct client_info *client = calloc(sizeof(*client), 1);
            if (client == NULL) {
                debug_msg("Could not allocate memory.\n");
                debug_func(SOCKETCLOSE(client_sockfd));
                continue;
            }

            // Set up the new client.
            client->ctrl_sockfd = client_sockfd;
            client->data_con_type = FTP_DATA_CONNECTION_NONE;
            strncpy(client->cur_path, default_directory,
                sizeof(client->cur_path));
            memcpy(&client->ctrl_sockaddr, &clientaddr,
                sizeof(client->ctrl_sockaddr));
#ifndef PS4
            client->umask = current_mask;
#endif
#if (defined(PS4) && defined(DEBUG_PS4)) || !defined(PS4)
            inet_ntop(AF_INET, &client->ctrl_sockaddr.sin_addr.s_addr,
                client->ipv4, sizeof(client->ipv4));
#endif
            client->facts.modify = 1;
            client->facts.size = 1;
            client->facts.type = 1;
            client->facts.unique = 0;
            client->facts.unix_group = 1;
            client->facts.unix_mode = 1;
            client->facts.unix_owner = 1;

            // Add the client to the client list.
            client_list_add(client);

            // Create a new thread for the client.
            if (pthread_create(&client->thid, NULL, client_thread, client)) {
                debug_msg("Could not create a client thread.\n");
                free(client);
                debug_func(SOCKETCLOSE(client_sockfd));
            }
        }
    }

    debug_func(SOCKETCLOSE(server_sockfd));
    debug_msg("Server thread exits.\n");
    return NULL;
}

// Initializes the program and starts the server thread.
int init(const char *ip, unsigned short port, char *default_directory)
{
    int ret;

    // Store server port and server IPv4 address globally.
    server_port = port;
    if (inet_pton(AF_INET, ip, &server_ip) == 0) {
        debug_msg("Invalid IPv4 address: \"%s\"\n", ip);
        return -1;
    }

    // Create client list mutex.
    ret = pthread_mutex_init(&client_list_mtx, NULL);
    if (ret) {
        debug_msg("Could not create the client list mutex (error %d).\n", ret);
        return -1;
    }

    // Create server thread.
    ret = pthread_create(&server_thid, NULL, server_thread, default_directory);
    if (ret) {
        debug_msg("Could not create the server thread (error %d).\n", ret);
        pthread_mutex_destroy(&client_list_mtx);
        return -1;
    }

    return 0;
}

// Cleans up and exits the program.
void fini()
{
    // Exit server thread.
    // Make the server thread's blocking accept() fail before attempting
    // to close the server socket. Simply closing a socket does not
    // unblock on PS4 and some other systems.
#ifdef PS4
    debug_func(sceNetSocketAbort(server_sockfd, 0));
#else
    debug_func(shutdown(server_sockfd, SHUT_RD));
#endif
    debug_msg("Waiting for server thread to exit...\n");
    debug_func(pthread_join(server_thid, NULL));

    // Exit client threads.
    debug_msg("Waiting for client threads to exit...\n");
    client_list_terminate();

    free(ftp_commands);
}
