The current PS4 FTP server payloads have some problems:

- [Fixed] A limitation that causes the server to keep sending data after a download is cancelled client-side. This can cause follow-up downloads to become slower and slower.
- [Fixed] Downloading multiple SELFs will corrupt the decryption, as the same temporary file is used.
- [Fixed] It is possible to load the payload multiple times, wasting memory.
- [Fixed] The server reports wrong file sizes for encrypted files when decryption is enabled, potentially corrupting resuming downloads.
- [Fixed] Files larger than 4 GiB may not resume properly due to an integer overflow.
- [Fixed] The server crashes when sending long commands.
- [Fixed] The server does not send an error message when the requested path does not exist.
- [Help needed] Connecting a client seems to cause a memory leak.

The improved FTP payload is available for download in the [release section](https://github.com/hippie68/ps4-ftp/releases/).

If you have ideas on how to improve the code and want to share, please let me know by creating an [issue](https://github.com/hippie68/ps4-ftp/issues).
Bash scripts to test FTP servers for some of the bugs are found in the [scripts directory](https://github.com/hippie68/ps4-ftp/tree/main/scripts).

Thanks to xvortex and Al-Azif for providing the source code. This FTP server is their work, and I just found and fixed some bugs.
