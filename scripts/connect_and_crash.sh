#!/bin/bash
# Checks if purely connecting and disconnecting causes a memory leak.
# If the FTP server has this bug, it will crash after about 14000 connections.

ps4_ip=192.168.x.x
ps4_port=1337

while :; do
  ((i++))
  echo "Connections so far: $i"
ftp -nv "$ps4_ip" $ps4_port<<EOF > /dev/null
user anonymous anonymous
bye
EOF
done
