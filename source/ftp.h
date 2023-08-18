// FTP server for PS4 and Linux.
// https://github.com/hippie68/ps4-ftp

#ifndef FTP_H
#define FTP_H

/// Shared preprocessor directives for all systems -----------------------------

#define CMD_LINE_BUF_SIZE PATH_MAX + 255
#define CRLF "\r\n"
#define FILE_BUF_SIZE 8192
#define DEFAULT_PATH "/"
#define DEFAULT_PORT 1337
#define RELEASE_VERSION "v1.08b (WIP)"

// Default FTP reply codes -----------------------------------------------------
// Commented reply codes mean their string needs to be generated dynamically.

// Syntax (x0z)
#define RC_200 "200 Command okay." CRLF
#define RC_500 "500 Syntax error, command unrecognized." CRLF
#define RC_501 "501 Syntax error in arguments." CRLF
#define RC_202 "202 Command not implemented, superfluous at this site." CRLF
#define RC_502 "502 Command not implemented." CRLF
#define RC_503 "503 Bad sequence of commands." CRLF
#define RC_504 "504 Command not implemented for that parameter." CRLF

// Information (x1z)
//              110 Restart marker reply.
//              211 System status, or system help reply.
//              212 Directory status reply.
//              213 File status reply.
//              214 Help message.
//              215 NAME system type.

// Connections (x2z)
//              120 Service ready in nnn minutes.
#define RC_220 "220 Service ready for new user." CRLF
#define RC_221 "221 Service closing control connection." CRLF
#define RC_421 "421 Service not available, closing control connection." CRLF
#define RC_125 "125 Data connection already open; transfer starting." CRLF
#define RC_225 "225 Data connection open; no transfer in progress." CRLF
#define RC_425 "425 Can't open data connection." CRLF
#define RC_226 "226 Closing data connection." \
               " Requested file action successful." CRLF
#define RC_426 "426 Connection closed; transfer aborted." CRLF
//              227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)

// Authentication and accounting (x3z)
#define RC_230 "230 User logged in, proceed." CRLF
#define RC_530 "530 Not logged in." CRLF
#define RC_331 "331 User name okay, need password." CRLF
#define RC_332 "332 Need account for login." CRLF
#define RC_532 "532 Need account for storing files." CRLF

// File system (x5z)
#define RC_150 "150 File status okay; about to open data connection." CRLF
#define RC_250 "250 Requested file action okay, completed." CRLF
//              257 "PATHNAME" created.
#define RC_350 "350 Requested file action pending further information." CRLF
#define RC_450 "450 Requested file action not taken." \
               " File temporarily unavailable." CRLF
#define RC_550 "550 Requested action not taken. File unavailable." CRLF
#define RC_451 "451 Requested action aborted." \
               " Local error in processing." CRLF
#define RC_551 "551 Requested action aborted. Page type unknown." CRLF
#define RC_452 "452 Requested action not taken." \
               " Insufficient storage space in system." CRLF
#define RC_552 "552 Requested file action aborted." \
               " Exceeded storage allocation." CRLF
#define RC_553 "553 Requested file action aborted." \
               " File name not allowed." CRLF

/// Preprocessor directives for PS4 --------------------------------------------

#ifdef PS4

#include "ps4.h"
#undef PATH_MAX
#define PATH_MAX 1024
#define FILE_PERM 0777
#define DIR_PERM 0777

// Uncomment this line or use compiler option -DDEBUG_PS4 to enable PS4 debug
// messages and send them to a computer.
//#define DEBUG_PS4

#ifdef DEBUG_PS4
// Adjust DEBUG_IP and DEBUG_PORT here (or use compiler options -DDEBUGIP and
// -DDEBUG_PORT) to match your computer's network setup.
// Print debug messages with the function debug_msg().
// In this order:
// 1. Listen to messages on your computer, e.g. via netcat: "netcat -l 9023".
// 2. Start the PS4 FTP server.
#ifndef DEBUG_IP
#define DEBUG_IP "192.168.x.x"
#endif
#ifndef DEBUG_PORT
#define DEBUG_PORT 9023
#endif
#define debug_msg(fmt, ...) \
    printf_debug("%s(): " fmt, __func__, ##__VA_ARGS__)
    // "##__VA_ARGS__" is a GCC extension, supported by other compilers, too.
    // It removes the preceding comma if "..." is missing.
#define log_msg(...) printf_debug(__VA_ARGS__)
#else
#define debug_msg(...)
#define log_msg(...)
#endif

// Other differences between non-PS4 and PS4.
#define accept(a, b, c) sceNetAccept(a, b, c)
#define bind(a, b, c) sceNetBind(a, b, c)
#define chmod(...) syscall(15, __VA_ARGS__)
#define connect(a, b,c) sceNetConnect(a, b, c)
#define ftruncate(...) syscall(480, __VA_ARGS__)
#define getsockname(a, b, c) sceNetGetsockname(a, b, c)
#define gmtime_r(a, b) gmtime_s(a, b)
#define htonl(x) sceNetHtonl(x)
#undef htons
#define htons(x) sceNetHtons(x)
#define inet_ntop(a, b, c, d) sceNetInetNtop(a, b, c, d)
#define inet_pton(a, b, c) sceNetInetPton(a, b, c)
#define INADDR_ANY IN_ADDR_ANY
#define listen(a, b) sceNetListen(a, b)
#define MSG_NOSIGNAL 0x20000
#define pthread_t ScePthread
#define pthread_create(a, b, c, d) scePthreadCreate(a, b, c, d, "")
#define pthread_detach(x) scePthreadDetach(x)
#define pthread_join(a, b) scePthreadJoin(a, b)
#define pthread_mutex_t ScePthreadMutex
#define pthread_mutex_destroy(x) scePthreadMutexDestroy(x)
#define pthread_mutex_init(a, b) scePthreadMutexInit(a, b, "")
#define pthread_mutex_lock(x) scePthreadMutexLock(x)
#define pthread_mutex_unlock(x) scePthreadMutexUnlock(x)
#define recv(a, b, c, d) sceNetRecv(a, b, c, d)
#define send(a, b, c, d) sceNetSend(a, b, c, d)
#define setsockopt(a, b, c, d, e) sceNetSetsockopt(a, b, c, d, e)
#define socket(a, b, c) sceNetSocket("", a, b, c)
#define SOCKETCLOSE(x) sceNetSocketClose(x)
#define SO_RCVTIMEO 0x1006
#define SO_REUSEADDR SCE_NET_SO_REUSEADDR
#define sleep(x) sceKernelSleep(x)
#define usleep(x) sceKernelUsleep(x)

/// Preprocessor directives for other systems (i.e. Linux) ---------------------

#else

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#ifndef NON_LINUX
#include <sys/sendfile.h>
#endif
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FILE_PERM 0666
#define DIR_PERM 0777

// Uncomment this line or use compiler option -DDEBUG to enable debug messages.
//#define DEBUG

#ifdef DEBUG
#define debug_msg(fmt, ...) \
    fprintf(stderr, "%s(): " fmt, __func__, ##__VA_ARGS__)
#else
#define debug_msg(...)
#endif

#define log_msg(...) fprintf(stderr, __VA_ARGS__)
#define printf_notification(...) // Only used for PS4.
#define SOCKETCLOSE(x) close(x)
#define UNUSED(x) (void) (x) // Prevents compiler warnings for unused variables.

#endif

/// ----------------------------------------------------------------------------

// Describes the client's data connection.
enum data_connection_type {
    FTP_DATA_CONNECTION_NONE,    // No opened data connection
    FTP_DATA_CONNECTION_ACTIVE,  // Data connection socket (.data_sockfd) used
    FTP_DATA_CONNECTION_PASSIVE, // Same as _ACTIVE, plus .pasv_sockfd used
};

// Stores the client's currently set MLST facts.
// When implementing a new fact, the following parts of ftp.c must be updated:
// cmd_FEAT(), cmd_OPTS_MLST, send_facts(), server_thread().
struct facts {
    int modify;     // Last modification time
    int size;       // Size in bytes
    int type;       // Entry type (dir, file, ...)
    int unique;     // Unique ID of file/directory
    int unix_group; // Group ID
    int unix_mode;  // Unix file permissions
    int unix_owner; // User ID
};

// Contains information about a connected client.
struct client_info {
#if (defined(PS4) && defined(DEBUG_PS4)) || !defined(PS4)
    char ipv4[16];                    // Client's IPv4 address in text form;
                                      // on Linux always used (for log output),
                                      // but on PS4 only used when debugging.
#endif
    pthread_t thid;                   // Client's thread UID
    int ctrl_sockfd;                  // Control connection socket
    int data_sockfd;                  // Data connection socket
    int pasv_sockfd;                  // PASV connection socket
    struct sockaddr_in ctrl_sockaddr; // Control socket information (IPv4, port)
    struct sockaddr_in data_sockaddr; // Data socket information
    enum data_connection_type data_con_type;
    char cmd_line[CMD_LINE_BUF_SIZE]; // Command line sent by clients
    char *cmd_args;                   // Command line arguments of .cmd_line
    char cur_path[PATH_MAX];          // Current FTP directory (no trailing '/')
    char rename_path[PATH_MAX];       // Rename path
    long long restore_point;          // Offset to resume outgoing files at
    char binary_flag;                 // File mode for APPE, RETR, STOR, STOU
    int umask;                        // Current file mode creation mask
    struct facts facts;               // Client's currently set MLST facts
    struct client_info *next;         // Next client in the client list
    struct client_info *prev;         // Previous client in the client list
};

// Describes whether an FTP command forbids, requires, or allows arguments.
enum cmd_args_flag {
    ARGS_NONE,
    ARGS_REQUIRED,
    ARGS_OPTIONAL,
};

// Contains an FTP command's name and associated function pointer.
struct ftp_command {
    char *name; // The FTP command's name (in capital letters)
    void (*function)(struct client_info *client); // The FTP command's function
    enum cmd_args_flag args_flag;
};

// Initializes and starts the FTP server.
// *ip: a valid IPv4 address
// port: a valid port number (1-65535)
int init(const char *ip, unsigned short port, char *default_directory);

// Terminates the FTP server.
void fini();

#endif
