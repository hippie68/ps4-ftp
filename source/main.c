// FTP server for PS4 and Linux.
// https://github.com/hippie68/ps4-ftp

#include "ftp.h"

#define POLLING_INTERVAL 5 // Time to wait between checks for `run`.

_Atomic int run = 1; // The server keeps running as long as the value is 1.

/// For PS4 --------------------------------------------------------------------

#ifdef PS4

// Copies the PS4's current IP address string to a buffer.
int get_ip_address(char *ip_address) {
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

int _main(struct thread *td) {
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
        if (run) {
            printf_notification("Listening on\nIP:     %s\nPort: %u",
                ip_address, DEFAULT_PORT);
        }

        // Loop until receiving the SHUTDOWN command, which sets run to 0.
        while (run) {
            sleep(POLLING_INTERVAL);
        }

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

void print_usage(FILE *stream, char *program_name) {
    fprintf(stream,
        "Usage: %s [OPTIONS] [PORT]\n\n"
        "Starts an anonymous FTP server in the current directory.\n\nOptions:\n"
        "  -h, --help  Print help information and quit.\n", program_name);
}

int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1],
        "--help") == 0))) {
        print_usage(argc > 2 ? stderr : stdout, argv[0]);
        return (argc > 2);
    }

    // Set IPv4 address or hostname, and port.
    char *ip = "127.0.0.1";
    unsigned short port = DEFAULT_PORT;
    if (argv[1]) {
        port = atoi(argv[1]);
        if (port == 0) {
            print_usage(stderr, argv[0]);
            return 1;
        }
    }

    // Start FTP server.
    char path[PATH_MAX];
    if (getcwd(path, sizeof(path)) == NULL) {
        if (init(ip, port, DEFAULT_PATH)) {
            return 1;
        }
    } else {
        if (init(ip, port, path)) {
            return 1;
        }
    }

    // Loop until receiving the SHUTDOWN command, which sets run to 0.
    while (run) {
        sleep(POLLING_INTERVAL);
    }

    // Exit FTP server.
    fini();
    return 0;
}

#endif
