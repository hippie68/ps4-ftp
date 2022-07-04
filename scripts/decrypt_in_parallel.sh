#!/bin/bash
# Tests if the currently running PS4 FTP server supports in-parallel
# decryption of SELF files.
# Before calling this script, make sure decryption is enabled (e.g. by sending
# the custom FTP command DECRYPT).

ps4_ip=192.168.x.x
ps4_port=1337
# Enter the path to an encrypted .prx file (on the PS4) here, starting with "/":
file='/safemode.elf'
# Number of files to download in-parallel
n=50

output_dir='parallel_decryption'

mkdir -p "$output_dir" && cd "$output_dir" || exit 1

for i in $(seq --equal-width 1 $n); do
  {
    echo "Downloading file $i ..."
    curl --silent "ftp://$ps4_ip:$ps4_port$file" > test_file_$i
    echo "-> Finished file $i"
  } &
done

wait
read -d ' ' ref_checksum < <(md5sum test_file_$n)
echo "Reference checksum (test_file_$n): $ref_checksum"
for i in $(seq --equal-width 1 $n); do
  echo -n "Checking test_file$i ... "
  read -d ' ' checksum < <(md5sum test_file_$i)
  echo -n "$checksum "
  if [[ $checksum != $ref_checksum ]]; then
    echo "ERROR"
    ((error++))
  else
    echo "OK"
  fi
done

if [[ $error ]]; then
  echo "Test failed with $error error(s): FTP server does not properly support in-parallel decryption".
else
  echo "Test succeeded: no errors found."
fi

cd ..
rm -r "$output_dir"
exit $error
