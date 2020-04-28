#include "crypto.h"
#include <vector>

using namespace std;

// taken from https://en.wikipedia.org/wiki/DES_supplementary_material

// key schedule
const int pc1[] = { // left
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 25,
    27, 19, 11, 3, 60, 52, 44, 36,
    // right
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
    37, 29, 21, 13, 5, 28, 20, 12, 4};

const int pc2[] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,
                   23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
                   41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                   44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

void des_cbc(const vector<uint8_t> input, const vector<uint8_t> key,
             const vector<uint8_t> iv, vector<uint8_t> output) {
  // block size = 8 bytes
  assert(iv.size() == 8);
  assert((input.size() % 8) == 0);
  output.resize(input.size());
  // key size = 8 bytes
  assert(key.size() == 8);
}