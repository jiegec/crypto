#include "crypto.h"
#include "util.h"
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

using namespace std;

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

void usage(char *name) {
  eprintf("Usage: %s OPTIONS INPUT OUTPUT\n", name);
  eprintf("       OPTIONS:\n");
  eprintf("         -d: decrypt\n");
  eprintf("         -e: encrypt\n");
  eprintf("         -D: digest\n");
  eprintf("         -l: lfsr\n");
  eprintf("         -a algo: use algo (one of: des, aes128, sm4, rc4, bm, "
          "sha224, sha256, sm3, sha3_224, sha3_256, sha3_384, sha3_512)\n");
  eprintf("         -k: key in hex\n");
  eprintf("         -i: iv in hex(all 0 when omitted)\n");
  eprintf("         -v: verbose\n");
  eprintf("       INPUT: path to input file or - for stdin\n");
  eprintf("       OUTPUT: path to output file or - for stdout\n");
}

enum Mode { None, Decrypt, Encrypt, Digest, LFSR };

int main(int argc, char *argv[]) {
  int c;
  string algo;
  string iv;
  string key;
  Mode mode = Mode::None;
  bool verbose = false;
  while ((c = getopt(argc, argv, "a:dDei:k:lv")) != -1) {
    switch (c) {
    case 'a':
      // algorithm
      algo = optarg;
      break;
    case 'd':
      // decrypt
      mode = Mode::Decrypt;
      break;
    case 'D':
      // digest
      mode = Mode::Digest;
      break;
    case 'e':
      // encrypt
      mode = Mode::Encrypt;
      break;
    case 'i':
      // iv
      iv = optarg;
      break;
    case 'k':
      // key
      key = optarg;
      break;
    case 'l':
      // lfsr
      mode = Mode::LFSR;
      break;
    case 'v':
      // verbose
      verbose = true;
      break;
    default:
      usage(argv[0]);
      return 1;
    }
  }

  if (optind + 2 != argc) {
    // input and output
    eprintf("Wrong number of arguments\n");
    usage(argv[0]);
    return 1;
  }
  if (mode == Mode::None) {
    eprintf("No mode specified(one of -d, -e, -D, -l)\n");
    usage(argv[0]);
    return 1;
  }

  string input = argv[optind];
  string output = argv[optind + 1];

  if (verbose) {
    eprintf("Algo: %s\n", algo.c_str());
    eprintf("IV: %s\n", iv.c_str());
    eprintf("key: %s\n", key.c_str());
    eprintf("mode: %d\n", mode);
  }

  std::vector<uint8_t> vec_iv;
  std::vector<uint8_t> vec_key;
  std::vector<uint8_t> vec_input;
  std::vector<uint8_t> vec_output;
  parse_hex(iv, vec_iv);
  parse_hex(key, vec_key);

  FILE *fp = stdin;
  if (input != "-") {
    // file
    fp = fopen(input.c_str(), "r");
    if (fp == NULL) {
      eprintf("Unable to read file: %s\n", input.c_str());
      return 1;
    }
  }

  const int len = 1024;
  uint8_t buffer[len];
  size_t read;
  while ((read = fread(buffer, 1, len, fp)) != 0) {
    vec_input.insert(vec_input.end(), buffer, buffer + read);
  }
  fclose(fp);

  if (algo == "des") {
    if (mode == Mode::Encrypt) {
      // pad to 8 bytes
      pkcs7_pad(vec_input, 8);
    }
    des_cbc(mode == Mode::Encrypt, vec_input, vec_key, vec_iv, vec_output);
    if (mode == Mode::Decrypt) {
      // unpad to 8 bytes
      pkcs7_unpad(vec_output, 8);
    }
  } else if (algo == "aes128") {
    if (mode == Mode::Encrypt) {
      // pad to 16 bytes
      pkcs7_pad(vec_input, 16);
    }
    aes128_cbc(mode == Mode::Encrypt, vec_input, vec_key, vec_iv, vec_output);
    if (mode == Mode::Decrypt) {
      // unpad to 16 bytes
      pkcs7_unpad(vec_output, 16);
    }
  } else if (algo == "sm4") {
    if (mode == Mode::Encrypt) {
      // pad to 16 bytes
      pkcs7_pad(vec_input, 16);
    }
    sm4_cbc(mode == Mode::Encrypt, vec_input, vec_key, vec_iv, vec_output);
    if (mode == Mode::Decrypt) {
      // unpad to 16 bytes
      pkcs7_unpad(vec_output, 16);
    }
  } else if (algo == "rc4") {
    rc4(vec_input, vec_key, vec_output);
  } else if (algo == "bm") {
    bm(vec_input, vec_output);
  } else if (algo == "sha224") {
    sha224(vec_input, vec_output);
  } else if (algo == "sha256") {
    sha256(vec_input, vec_output);
  } else if (algo == "sha512") {
    sha512(vec_input, vec_output);
  } else if (algo == "sm3") {
    sm3(vec_input, vec_output);
  } else if (algo == "sha3_224") {
    sha3_224(vec_input, vec_output);
  } else if (algo == "sha3_256") {
    sha3_256(vec_input, vec_output);
  } else if (algo == "sha3_384") {
    sha3_384(vec_input, vec_output);
  } else if (algo == "sha3_512") {
    sha3_512(vec_input, vec_output);
  } else {
    // TODO
    eprintf("Unsupported algo: %s\n", algo.c_str());
    usage(argv[0]);
    return 1;
  }

  fp = stdout;
  if (output != "-") {
    // file
    fp = fopen(output.c_str(), "wb");
    if (fp == NULL) {
      eprintf("Unable to write file: %s\n", input.c_str());
      return 1;
    }
  }
  size_t offset = 0;
  while (offset < vec_output.size()) {
    size_t write =
        fwrite(&vec_output[offset], 1, vec_output.size() - offset, fp);
    offset += write;
  }
  fclose(fp);

  return 0;
}