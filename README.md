Current FTP server payloads have a flaw that causes the server to keep sending data after a download is cancelled client-side. This will cause follow-up downloads to become slower and slower. As a quick solution, until we have better FTP servers, I added a kill switch that immediately stops all downloads. It is invoked by the custom command KILL.

The compiled FTP payload is available in the [release section](https://github.com/hippie68/ps4-ftp/releases/).
