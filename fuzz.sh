#!/bin/sh
set -v
set -e
OPENSSL=/usr/local/opt/openssl/bin/openssl
dd if=/dev/urandom of=input bs=1K count=16

# des
$OPENSSL enc -v -des-cbc -iv 0000000000000000 -K e0e0e0e0f1f1f1f1 -in input -out output
./crypto -v -a des -i 0000000000000000 -k e0e0e0e0f1f1f1f1 -d output decrypted
diff input decrypted
rm output decrypted
./crypto -v -a des -i 0000000000000000 -k e0e0e0e0f1f1f1f1 -e input output
$OPENSSL enc -v -des-cbc -iv 0000000000000000 -K e0e0e0e0f1f1f1f1 -d -in output -out decrypted
diff input decrypted
rm output decrypted

# aes
$OPENSSL enc -v -aes-128-cbc -iv 00000000000000000000000000000000 -K e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -in input -out output
./crypto -v -a aes128 -i 00000000000000000000000000000000 -k e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -d output decrypted
diff input decrypted
rm output decrypted
./crypto -v -a aes128 -i 00000000000000000000000000000000 -k e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -e input output
$OPENSSL enc -v -aes-128-cbc -iv 00000000000000000000000000000000 -K e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -d -in output -out decrypted
diff input decrypted
rm output decrypted

# sm4
$OPENSSL enc -v -sm4-cbc -iv 00000000000000000000000000000000 -K e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -in input -out output
./crypto -v -a sm4 -i 00000000000000000000000000000000 -k e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -d output decrypted
diff input decrypted
rm output decrypted
./crypto -v -a sm4 -i 00000000000000000000000000000000 -k e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -e input output
$OPENSSL enc -v -sm4-cbc -iv 00000000000000000000000000000000 -K e0e0e0e0f1f1f1f1e0e0e0e0f1f1f1f1 -d -in output -out decrypted
diff input decrypted
rm output decrypted

echo 'all correct!'