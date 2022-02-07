The current PS4 FTP server payloads have some problems:

- [Worked around] A limitation that causes the server to keep sending data after a download is cancelled client-side. This can cause follow-up downloads to become slower and slower. As a quick solution, until we have better FTP servers, I added a kill switch that immediately stops all downloads. It is invoked by the custom command KILL.
- [Fixed] Downloading multiple SELFs will corrupt the decryption, as the same temporary file is used.
- [Fixed] It is possible to load the payload multiple times, wasting memory.
- [Fixed] The server reports wrong file sizes for encrypted files when decryption is enabled, potentially corrupting resuming downloads.
- [Fixed] Files larger than 4 GiB may not resume properly due to an integer overflow.
- [Help needed] Connecting a client seems to cause a memory leak, which will eventually crash the server after several thousand new client connections.

If you have ideas on how to improve the code and want to share, let me know.

The compiled FTP payload is available in the [release section](https://github.com/hippie68/ps4-ftp/releases/).

Thanks to xvortex and Al-Azif for providing the source base.
