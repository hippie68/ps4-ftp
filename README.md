The current PS4 FTP server payloads have some problems:

- [Worked around] A limitation that causes the server to keep sending data after a download is cancelled client-side. This can cause follow-up downloads to become slower and slower. As a quick solution, until we have better FTP servers, I added a kill switch that immediately stops all downloads. It is invoked by the custom command KILL.
- [Fixed] Downloading multiple SELFs will corrupt the decryption, as the same temporary file is used.
- [Fixed] It is possible to load the payload multiple times, wasting memory.
- [Help needed] Downloading thousands of files by using command line clients will eventually crash the server.

If you have ideas on how to improve the code and want to share, let me know.

The compiled FTP payload is available in the [release section](https://github.com/hippie68/ps4-ftp/releases/).

Thanks to xvortex and Al-Azif for providing the source base.
