#include "crypto.h"
#include <cassert>
#include <vector>

using namespace std;

// reference:
// http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
// tables are taken
// from https://en.wikipedia.org/wiki/DES_supplementary_material

// Initial permutation
const int ip[] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                  57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
                  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

// Final permutation
const int ip1[] = {40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55,
                   23, 63, 31, 38, 6,  46, 14, 54, 22, 62, 30, 37, 5,
                   45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60,
                   28, 35, 3,  43, 11, 51, 19, 59, 27, 34, 2,  42, 10,
                   50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25};

// Expansion
const int e[] = {32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
                 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
                 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

// Permutation
const int p[] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
                 2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25};

// 8 S-boxes
const int s[8][64] = {
    {14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
     0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
     4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
     15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13},
    {15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
     3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
     0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
     13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9},
    {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
     13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
     13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
     1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12},
    {7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
     13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
     10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
     3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14},
    {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
     14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
     4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
     11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3},
    {12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
     10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
     9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
     4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13},
    {4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
     13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
     1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
     6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12},
    {13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
     1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
     7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
     2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11}};

// preprocessed S-box
bool preprocessed = false;
uint64_t s_preprocessed[8][64] = {{0}};

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

// reverse 8bit number
// https://stackoverflow.com/questions/2602823/in-c-c-whats-the-simplest-way-to-reverse-the-order-of-bits-in-a-byte
inline uint8_t reverse(uint8_t b) {
  b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
  b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
  b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
  return b;
}

// reverse 32bit number
// https://helloacm.com/how-to-reverse-bits-for-32-bit-unsigned-integer-in-cc/
inline uint32_t reverse32(uint32_t n) {
  n = ((n >> 1) & 0x55555555) | ((n << 1) & 0xaaaaaaaa);
  n = ((n >> 2) & 0x33333333) | ((n << 2) & 0xcccccccc);
  n = ((n >> 4) & 0x0f0f0f0f) | ((n << 4) & 0xf0f0f0f0);
  n = ((n >> 8) & 0x00ff00ff) | ((n << 8) & 0xff00ff00);
  n = ((n >> 16) & 0x0000ffff) | ((n << 16) & 0xffff0000);
  return n;
}

// reverse 32bit number within 4bits
inline uint32_t reverse32_4(uint32_t n) {
  n = ((n >> 1) & 0x55555555) | ((n << 1) & 0xaaaaaaaa);
  n = ((n >> 2) & 0x33333333) | ((n << 2) & 0xcccccccc);
  return n;
}

template <int N>
inline uint64_t apply_permutation(uint64_t input, const int perm[N]) {
  uint64_t output = 0;
  for (int i = N - 1; i >= 0; i--) {
    output = (output << 1) | ((input & ((uint64_t)1 << (perm[i] - 1))) != 0);
  }
  return output;
}

// 28bit shift rotate right
inline uint64_t rotate(uint64_t num) { return (num >> 1) | ((num & 1) << 27); }

// Richard Outerbridge's optimization
// https://crypto.stackexchange.com/questions/59190/des-how-does-richard-outerbridges-initial-permutation-operate/59212#59212
// IP
inline uint64_t inital_permutation(uint64_t input) {
  // a faster implementation of:
  // uint64_t after_ip = apply_permutation<64>(init_data, ip);
  uint32_t leftt = reverse32(input);
  uint32_t right = reverse32(input >> 32);
  uint32_t work;

  work = ((right >> 4) ^ leftt) & 0x0f0f0f0f;
  leftt ^= work;
  right ^= (work << 4);

  work = ((leftt >> 16) ^ right) & 0x0000ffff;
  right ^= work;
  leftt ^= (work << 16);

  work = ((right >> 2) ^ leftt) & 0x33333333;
  leftt ^= work;
  right ^= (work << 2);

  work = ((leftt >> 8) ^ right) & 0x00ff00ff;
  right ^= work;
  leftt ^= (work << 8);

  work = ((right >> 1) ^ leftt) & 0x55555555;
  leftt ^= work;
  right ^= (work << 1);

  return (((uint64_t)reverse32_4(leftt)) << 32) | reverse32_4(right);
}

// preprocess sbox and p into one
void preprocess() {
  for (int box = 0; box < 8; box++) {
    for (uint64_t window = 0; window < (1 << 6); window++) {
      // row: bit 0 | bit 5
      // col: bit 1 | bit 2 | bit 3 | bit 4
      // index = row << 4 | col
      uint64_t row = ((window & 1) << 1) | (window >> 5);
      uint64_t col = ((window & 0x2) << 2) | ((window & 0x4)) |
                     ((window & 0x8) >> 2) | ((window & 0x10) >> 4);
      uint64_t index = (row << 4) | col;
      uint64_t sbox = s[box][index];
      // reverse bit order in sbox
      sbox = ((sbox & 0x1) << 3) | ((sbox & 0x2) << 1) | ((sbox & 0x4) >> 1) |
             ((sbox & 0x8) >> 3);
      sbox = sbox << (box * 4);
      s_preprocessed[box][window] = apply_permutation<32>(sbox, p);
    }
  }
}

// optimization of:
// uint64_t after_expansion = apply_permutation<48>(right, e);
inline uint64_t expansion(uint64_t input) {
  uint64_t res = 0;
  // 0: 5 4 3 2 1 32
  res |= ((input & 0b11111) << 1) | ((input & ((uint64_t)1 << 31)) >> 31);
  // 6: 9 8 7 6 5 4
  res |= ((input & (0b111111LL << 3)) << 3);
  // 12: 13 12 11 10 9 8
  res |= ((input & (0b111111LL << 7)) << 5);
  // 18: 17 16 15 14 13 12
  res |= ((input & (0b111111LL << 11)) << 7);
  // 24: 21 20 19 18 17 16
  res |= ((input & (0b111111LL << 15)) << 9);
  // 32: 25 24 23 22 21 20
  res |= ((input & (0b111111LL << 19)) << 11);
  // 40: 29 28 27 26 25 24
  res |= ((input & (0b111111LL << 23)) << 13);
  // 48: 1 32 31 30 29 28
  res |= ((input & (0b11111LL << 27)) << 15) | ((input & 1) << 47);

  return res;
}

void des_cbc(bool encrypt, const vector<uint8_t> &input,
             const vector<uint8_t> &key, const vector<uint8_t> &iv,
             vector<uint8_t> &output) {
  // block size = 8 bytes
  assert(iv.size() == 8);
  assert((input.size() % 8) == 0);
  output.resize(input.size());
  // key size = 8 bytes
  assert(key.size() == 8);

  // do some preprocessing
  if (!preprocessed) {
    preprocess();
    preprocessed = true;
  }

  // convert key to 64bit integer
  uint64_t init_key = 0;
  for (int i = 0; i < 8; i++) {
    // reverse bit order
    init_key |= (uint64_t)(reverse(key[i])) << (8 * i);
  }

  // key scheduling part
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

    uint64_t current_key = (left << 28) | right;
    // PC2
    uint64_t after_pc2 = apply_permutation<48>(current_key, pc2);
    // use reverse subkeys for decrypt
    if (encrypt) {
      subkeys[i] = after_pc2;
    } else {
      subkeys[15 - i] = after_pc2;
    }
  }

  // convert iv to 64bit integer
  uint64_t init_iv = 0;
  for (int i = 0; i < 8; i++) {
    // reverse bit order
    init_iv |= (uint64_t)(reverse(iv[i])) << (8 * i);
  }

  // for each block
  for (size_t offset = 0; offset < input.size(); offset += 8) {
    // convert data to 64bit integer
    uint64_t init_data = 0;
    for (int i = 0; i < 8; i++) {
      // reverse bit order
      init_data |= (uint64_t)(reverse(input[offset + i])) << (8 * i);
    }
    // in encryption, plain text is xored with last iv
    if (encrypt) {
      init_data ^= init_iv;
    }

    // ip
    // uint64_t after_ip = apply_permutation<64>(init_data, ip);
    // optimized to:
    uint64_t after_ip = inital_permutation(init_data);
    // printf("after ip: %llx\n", after_ip);

    // swap left and right before first round
    uint64_t left = after_ip & (((uint64_t)1 << 32) - 1);
    uint64_t right = after_ip >> 32;

    for (int round = 0; round < 16; round++) {
      // expand
      // uint64_t after_expansion = apply_permutation<48>(right, e);
      // optimized to:
      uint64_t after_expansion = expansion(right);

      // xor with subkey
      uint64_t xored = after_expansion ^ subkeys[round];

      // split xored into 8 6-bit groups and pass to each s-box and p
      uint64_t after_sbox_p = 0;
      for (int box = 0; box < 8; box += 1) {
        uint64_t window = (xored >> (box * 6)) & ((1 << 6) - 1);
        uint64_t sbox_p = s_preprocessed[box][window];
        after_sbox_p ^= sbox_p;
      }

      uint64_t new_left = right;
      uint64_t new_right = left ^ after_sbox_p;
      left = new_left;
      right = new_right;
    }

    // concat right and left
    uint64_t after_rounds = (left << 32) | right;
    // apply IP^{-1}
    uint64_t after_ip1 = apply_permutation<64>(after_rounds, ip1);

    // in decryption, plain text is xored with iv
    if (!encrypt) {
      after_ip1 ^= init_iv;
    }
    // write to output in reverse bit order
    for (int i = 0; i < 8; i++) {
      // reverse bit order
      output[offset + i] = reverse((after_ip1 >> (8 * i)) & 0xff);
    }
    // in encryption, cipher text is used as new iv
    if (encrypt) {
      init_iv = after_ip1;
    } else {
      // in decryption, cipher text is used as new iv
      init_iv = init_data;
    }
  }
}
