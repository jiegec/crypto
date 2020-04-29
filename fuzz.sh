#!/bin/sh
set -v
set -e
dd if=/dev/urandom of=input bs=1K count=16
openssl enc -v -des-cbc -iv 0000000000000000 -K e0e0e0e0f1f1f1f1 -in input -out output
./crypto -v -a des -i 0000000000000000 -k e0e0e0e0f1f1f1f1 -d output decrypted
diff input decrypted