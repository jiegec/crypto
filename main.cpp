#include <stdio.h>
#include <string>
#include <unistd.h>

using namespace std;

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

void usage(char *name) {
  eprintf("Usage: %s OPTIONS INPUT OUTPUT\n", name);
  eprintf("       OPTIONS:\n");
  eprintf("         -d: decrypt\n");
  eprintf("         -e: encrypt\n");
  eprintf("         -D: digest\n");
  eprintf("         -l: lfsr\n");
  eprintf("         -a algo: use algo (one of: des, aes-128, sm4, rc4, bm, "
          "sha2, sm3, sha3)\n");
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

  if (algo == "des") {

  } else {
    // TODO
    eprintf("Unsupported algo: %s\n", algo.c_str());
    usage(argv[0]);
    return 1;
  }

  return 0;
}