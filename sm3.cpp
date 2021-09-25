#include "crypto.h"
#include "util.h"

// reference:
// https://tools.ietf.org/html/draft-oscca-cfrg-sm3-02

// 4.4.  Permutation Functions P_0 and P_1
inline uint32_t p_0(uint32_t x) {
  return x ^ ((x << 9) | (x >> 23)) ^ ((x << 17) | (x >> 15));
}
inline uint32_t p_1(uint32_t x) {
  return x ^ ((x << 15) | (x >> 17)) ^ ((x << 23) | (x >> 9));
}

void sm3(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  // 256 bits = 32bytes
  output.resize(32);

  uint32_t V[8] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                   0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

  // preprocessing
  std::vector<uint8_t> preprocessed = input;
  hash_pad(preprocessed, false);

  for (size_t offset = 0; offset < preprocessed.size(); offset += 64) {
    uint32_t w[68];
    uint32_t w1[64];

    // B_i = W_0 || ... || W_15
    // copy preprocessed to w[0..15]
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint32_t)preprocessed[offset + 4 * i] << 24) |
             ((uint32_t)preprocessed[offset + 4 * i + 1] << 16) |
             ((uint32_t)preprocessed[offset + 4 * i + 2] << 8) |
             (uint32_t)preprocessed[offset + 4 * i + 3];
    }

    // 5.3.2.  Message Expansion Function ME
    // extend 16 words to w[16..67]
    for (int i = 16; i < 68; i++) {
      // W_j = P_1(W_{j - 16} xor W_{j - 9} xor (W_{j - 3} <<< 15)) xor
      // (W_{j - 13} <<< 7) xor W_{ j - 6 }
      uint32_t temp =
          p_1(w[i - 16] ^ w[i - 9] ^ ((w[i - 3] << 15) | (w[i - 3] >> 17)));
      w[i] = temp ^ ((w[i - 13] << 7) | (w[i - 13] >> 25)) ^ w[i - 6];
    }

    for (int i = 0; i < 64; i++) {
      // W'_j = W_j xor W_{j + 4}
      w1[i] = w[i] ^ w[i + 4];
    }

    // E_i = W_0 || ... || W_67 || W'_0 || ... || W'_63

    // 5.3.3. Compression Function CF

    uint32_t a = V[0];
    uint32_t b = V[1];
    uint32_t c = V[2];
    uint32_t d = V[3];
    uint32_t e = V[4];
    uint32_t f = V[5];
    uint32_t g = V[6];
    uint32_t h = V[7];

    // compression main loop
    for (int i = 0; i < 64; i++) {
      // 4.2.  Constants T_j
      uint32_t tj = (i <= 15) ? 0x79cc4519 : 0x7a879d8a;

      uint32_t ss1 = (((a << 12) | (a >> 20)) + e +
                      ((tj << (i % 32)) | (tj >> (32 - i % 32))));
      ss1 = (ss1 << 7) | (ss1 >> 25);
      uint32_t ss2 = ss1 ^ ((a << 12) | (a >> 20));
      // 4.3. Boolean Functions FF_j and GG_j
      uint32_t tt1;
      // FF_j(a, b, c)
      if (i <= 15) {
        tt1 = a ^ b ^ c;
      } else {
        tt1 = (a & b) | (a & c) | (b & c);
      }
      tt1 += d + ss2 + w1[i];
      uint32_t tt2;
      // GG_j(e, f, g)
      if (i <= 15) {
        tt2 = e ^ f ^ g;
      } else {
        tt2 = (e & f) | ((~e) & g);
      }
      tt2 += h + ss1 + w[i];

      d = c;
      c = (b << 9) | (b >> 23);
      b = a;
      a = tt1;
      h = g;
      g = (f << 19) | (f >> 13);
      f = e;
      e = p_0(tt2);
    }

    V[0] ^= a;
    V[1] ^= b;
    V[2] ^= c;
    V[3] ^= d;
    V[4] ^= e;
    V[5] ^= f;
    V[6] ^= g;
    V[7] ^= h;
  }

  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 4; j++) {
      // big endian
      output[4 * i + j] = (V[i] >> (8 * (3 - j))) & 0xFF;
    }
  }
}