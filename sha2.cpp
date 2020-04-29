#include "crypto.h"

// reference:
// https://en.wikipedia.org/wiki/SHA-2
// https://tools.ietf.org/html/rfc6234
// https://docs.google.com/spreadsheets/d/1mOTrqckdetCoRxY5QkVcyQ7Z0gcYIH-Dc0tu7t9f7tw/edit#gid=2107569783

const uint32_t sha256_k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  // 256 bits = 32bytes
  output.resize(32);

  uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  // preprocessing
  uint64_t length = input.size();
  // 9: 8-byte length + 0x80
  // padding: 80 00 00 00 ... [64-bit length]
  size_t real_length = (length + 9 + 63) & ~63;
  std::vector<uint8_t> preprocessed = input;
  preprocessed.resize(real_length);
  preprocessed[length] = 0x80;
  // big endian
  for (int i = 0; i < 8; i++) {
    preprocessed[real_length - i - 1] = ((length * 8) >> (8 * i)) & 0xFF;
  }

  for (size_t offset = 0; offset < real_length; offset += 64) {
    uint32_t w[64];

    // copy preprocessed to w[0..15]
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint32_t)preprocessed[offset + 4 * i] << 24) |
             ((uint32_t)preprocessed[offset + 4 * i + 1] << 16) |
             ((uint32_t)preprocessed[offset + 4 * i + 2] << 8) |
             (uint32_t)preprocessed[offset + 4 * i + 3];
    }

    // extend 16 words to w[16..63]
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^
                    ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >> 3);
      uint32_t s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^
                    ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    // compression main loop
    for (int i = 0; i < 64; i++) {
      uint32_t s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                    ((e >> 25) | (e << 7));
      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t temp1 = h + s1 + ch + sha256_k[i] + w[i];
      uint32_t s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
                    ((a >> 22) | (a << 10));
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = s0 + maj;

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
  }

  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 4; j++) {
      // big endian
      output[4 * i + j] = (H[i] >> (8 * (3 - j))) & 0xFF;
    }
  }
}