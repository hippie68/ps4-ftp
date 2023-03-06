// FTP server for PS4 and Linux.
// https://github.com/hippie68/ps4-ftp

#define _FILE_OFFSET_BITS 64

#include "ftp.h"

#define POLLING_INTERVAL 5 // Time to wait between checks for `run`.

_Atomic int run = 1; // The server keeps running as long as the value is 1.

/// For PS4 --------------------------------------------------------------------

#ifdef PS4

// Copies the PS4's current IP address string to a buffer.
int get_ip_address(char *ip_address)
{
    SceNetCtlInfo info;
    memset_s(&info, sizeof(SceNetCtlInfo), 0, sizeof(SceNetCtlInfo));

    int ret = sceNetCtlInit();
    if (ret >= 0) {
        ret = sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, &info);
        if (ret >= 0) {
            memcpy(ip_address, info.ip_address, sizeof(info.ip_address));
            sceNetCtlTerm();
            return ret;
        }
    }

    return -1;
}

int _main(struct thread *td)
{
    UNUSED(td);

    initKernel();
    initLibc();
    initNetwork();
    initPthread();
    jailbreak();
    mmap_patch();
    initSysUtil();

#ifdef DEBUG_PS4
    DEBUG_SOCK = SckConnect(DEBUG_IP, DEBUG_PORT);
#endif

    printf_notification("FTP server " RELEASE_VERSION " by hippie68");

    char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN] = { 0 };
    if (get_ip_address(ip_address) >= 0) {
        // Start FTP server.
        init(ip_address, DEFAULT_PORT, DEFAULT_PATH);

        // server_thread() in ftp.c will set run to 0 on binding error - give
        // it some time to possibly do so.
        sleep(3);

        // Display IP address and port in form of a PS4 notification popup.
        if (run)
            printf_notification("Listening on\nIP:     %s\nPort: %u",
                ip_address, DEFAULT_PORT);

        // Loop until receiving the SHUTDOWN command, which sets run to 0.
        while (run)
            sleep(POLLING_INTERVAL);

        // Exit FTP server.
        fini();
    } else {
        printf_notification("Unable to get the PS4's IP address");
    }

    printf_notification("Shutting down FTP server...");

#ifdef DEBUG_PS4
    sceNetSocketClose(DEBUG_SOCK);
#endif

    return 0;
}

/// For non-PS4 ----------------------------------------------------------------

#else

#include <getopt.h>

static char *program_name;
int read_only_mode = 0; // Write commands are disabled if the value is 1.

void print_usage(int exit_code)
{
    fprintf(exit_code ? stderr : stdout,
        "Usage: %s [OPTIONS] [PORT]\n\n"
        "Starts an anonymous FTP server in the current directory.\n"
        "\nOptions:\n"
        "  -h, --help       Print help information and quit.\n"
        "      --read-only  Start the server in read-only mode.\n"
        , program_name);
    exit(exit_code);
}

int main(int argc, char **argv)
{
    program_name = strrchr(argv[0], '/');
    if (program_name)
        program_name++;
    else
        program_name = argv[0];

    // Check command line arguments.
    static const struct option long_opts[] = {
        { "help",      no_argument, NULL,            'h' },
        { "read-only", no_argument, &read_only_mode, 1   },
        { NULL }
    };
    int c;
    while ((c = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        switch (c) {
            case 'h':
                print_usage(EXIT_SUCCESS);
                break;
            case '?':
                print_usage(EXIT_FAILURE);
                break;
        }
    }
    argc -= optind;
    argv += optind;

    // Set FTP server port.
    unsigned short server_port;
    if (argc == 0)
        server_port = DEFAULT_PORT;
    else if (argc > 1) // Allow only 1 operand: "PORT".
        print_usage(EXIT_FAILURE);
    else if ((server_port = atoi(argv[0])) == 0) {
        fprintf(stderr,
            "PORT must be a number between 1 and 65535 (usually > 1023).\n");
        print_usage(EXIT_FAILURE);
    }

    // Start FTP server.
    char pathbuf[PATH_MAX];
    char *path = getcwd(pathbuf, sizeof(pathbuf));
    if (path == NULL)
        path = DEFAULT_PATH;
    if (init("127.0.0.1", server_port, path))
        exit(EXIT_FAILURE);

    // Loop until receiving the SHUTDOWN command, which sets run to 0.
    while (run)
        sleep(POLLING_INTERVAL);

    // Exit FTP server.
    fini();
    exit(EXIT_SUCCESS);
}

#endif
