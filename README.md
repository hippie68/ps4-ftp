# FTP server for PS4 and Linux

This is an improved version of the "FTPS4" FTP server payload (https://github.com/xerpi/FTPS4) that fixes a few major bugs and many small ones. Plus the server now runs on Linux, too!

Some of the most important bug fixes:

- [Fixed] A limitation that causes the server to keep sending data after a download is cancelled client-side. This can cause follow-up downloads to become slower and slower.
- [Fixed] Downloading multiple SELFs will corrupt the decryption, as the same temporary file is used.
- [Fixed] It is possible to load the payload multiple times, wasting memory.
- [Fixed] The server reports wrong file sizes for encrypted files when decryption is enabled, potentially corrupting resuming downloads.
- [Fixed] Files larger than 4 GiB may not resume properly due to an integer overflow.
- [Fixed] The server crashes when sending long commands.
- [Fixed] The server does not send an error message when the requested path does not exist.
- [Fixed] Connecting a client causes a memory leak.
- [Fixed] Uploads don't resume at the specified REST marker.

New features:

- FTP commands NLST, MDTM, MLSD, MLST, OPTS, "SITE CHMOD", and "SITE UMASK", which FTP clients and scripts can now make use of.
- Logging and debugging: full client/server dialog output and debug output.
- Also runs on Linux, optionally in read-only mode.

The compiled PS4 payload is available for download in the [release section](https://github.com/hippie68/ps4-ftp/releases/).
To exit the running payload at any time, send the custom FTP command SHUTDOWN (or, if the payload is running inside the web browser, close the browser).

## How to compile for PS4

1. Set up the PS4 payload SDK from https://github.com/Scene-Collective/ps4-payload-sdk.
2. In the ps4-ftp directory, type "make clean && make" to compile.

Optional: if you want to help debug, add your computer's IP address and port as described in the file ftp.h, section "Preprocessor directives for PS4". Uncomment the line that says "//#define DEBUG_PS4" or use compiler option -DDEBUG_PS4. It will make the code larger and the FTP server less responsive, so only do this if you want to debug.
On your computer, start netcat or any similar TCP/IP program to listen to the debug output. The computer's IP address and the specified port must match those saved in ftp.h. E.g.:

```
    netcat -l 9023
```

netcat must be started before starting the payload.

## How to compile for Linux

```
    gcc source/*.c -pthread -Wall -Wextra --pedantic -s -O3 -o ftpserver
```

## How to run on Linux

```
Usage: ftpserver [OPTIONS] [PORT]

Starts an anonymous FTP server in the current directory.

Options:
  -h, --help       Print help information and quit.
      --read-only  Start the server in read-only mode.
```

The Linux version starts an anonymous FTP server in the current directory, with the default port being 1337. It will print a log that displays connected clients and the client-server dialogues. If you want to see debug output, too, add the compiler option -DDEBUG.
Press CTRL-C to exit the running server at any time (or send the custom FTP command SHUTDOWN).

## How to compile for other operating systems
The code might compile on other Unix-like operating systems by specifying the macro "NON_LINUX", but this is not tested.

---

If you have ideas on how to improve the code and want to share, please let me know by creating an [issue](https://github.com/hippie68/ps4-ftp/issues).
Bash scripts to test other FTP servers for some of the bugs are found in the [scripts directory](https://github.com/hippie68/ps4-ftp/tree/main/scripts).

#### Credits
Development chain: [xerpi](https://github.com/xerpi/FTPS4) -> [idc](https://github.com/idc/libftps4) -> [xvortex](https://github.com/xvortex/ps4-ftp-vtx) -> [Scene-Collective](https://github.com/Scene-Collective/ps4-ftp) -> [hippie68](https://github.com/hippie68/ps4-ftp).
And thanks to SiSTRo for pointing out problems in the original FTPS4 code!
