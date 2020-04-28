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

// https://stackoverflow.com/questions/2602823/in-c-c-whats-the-simplest-way-to-reverse-the-order-of-bits-in-a-byte
inline uint8_t reverse(uint8_t b) {
  b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
  b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
  b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
  return b;
}

template<int N>
inline uint64_t apply_permutation(uint64_t input, const int perm[N]) {
  uint64_t output = 0;
  for (int i = N - 1; i >= 0; i--) {
    output = (output << 1) | ((input & ((uint64_t)1 << (perm[i] - 1))) != 0);
  }
  return output;
}

// 28bit shift rotate right
inline uint64_t rotate(uint64_t num) { return (num >> 1) | ((num & 1) << 27); }

void des_cbc(const vector<uint8_t> &input, const vector<uint8_t> &key,
             const vector<uint8_t> &iv, vector<uint8_t> &output) {
  // block size = 8 bytes
  assert(iv.size() == 8);
  assert((input.size() % 8) == 0);
  output.resize(input.size());
  // key size = 8 bytes
  assert(key.size() == 8);

  // convert key to 64bit integer
  uint64_t init_key = 0;
  for (int i = 0; i < 8; i++) {
    // reverse bit order
    init_key |= (uint64_t)(reverse(key[i])) << (8 * i);
  }

  // PC1
  uint64_t after_pc1 = apply_permutation<56>(init_key, pc1);

  // left and right part
  uint64_t left = after_pc1 >> 28;
  uint64_t right = after_pc1 & ((1 << 28) - 1);

  // 16 subkeys
  uint64_t subkeys[16];
  for (int i = 0; i <= 15; i++) {
    // rotate
    left = rotate(left);
    right = rotate(right);
    // for rounds other than 1, 2, 9, 16, rotate twice
    if (i != 0 && i != 1 && i != 8 && i != 15) {
      // rotate
      left = rotate(left);
      right = rotate(right);
    }
    // printf("Round %d: left %llx right %llx\n", i, left, right);

    uint64_t current_key = (left << 28) | right;
    // PC2
    uint64_t after_pc2 = apply_permutation<48>(current_key, pc2);
    subkeys[i] = after_pc2;
    // printf("Subkey %d: %llx\n", i, after_pc2);
  }
}