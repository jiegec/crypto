#include "crypto.h"
#include "util.h"

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

// common code for SHA-224 and SHA-256
void sha224_256(const std::vector<uint8_t> &input, std::vector<uint8_t> &output,
                uint32_t H[8]) {
  // 256 bits = 32bytes
  output.resize(32);

  // preprocessing
  std::vector<uint8_t> preprocessed = input;
  hash_pad(preprocessed, false);

  for (size_t offset = 0; offset < preprocessed.size(); offset += 64) {
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

// difference: H and output length
void sha224(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  uint32_t H[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                   0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

  sha224_256(input, output, H);
  // 224
  output.resize(28);
}
void sha256(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  sha224_256(input, output, H);
}

const uint64_t sha512_k[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

// common code for SHA-384 and SHA-512
void sha384_512(const std::vector<uint8_t> &input, std::vector<uint8_t> &output,
                uint64_t H[8]) {
  // 512 bits = 64bytes
  output.resize(64);

  // preprocessing
  std::vector<uint8_t> preprocessed = input;
  hash_pad(preprocessed, false, 128);

  for (size_t offset = 0; offset < preprocessed.size(); offset += 128) {
    uint64_t w[80];

    // copy preprocessed to w[0..15]
    for (int i = 0; i < 16; i++) {
      w[i] = ((uint64_t)preprocessed[offset + 8 * i] << 56) |
             ((uint64_t)preprocessed[offset + 8 * i + 1] << 48) |
             ((uint64_t)preprocessed[offset + 8 * i + 2] << 40) |
             ((uint64_t)preprocessed[offset + 8 * i + 3] << 32) |
             ((uint64_t)preprocessed[offset + 8 * i + 4] << 24) |
             ((uint64_t)preprocessed[offset + 8 * i + 5] << 16) |
             ((uint64_t)preprocessed[offset + 8 * i + 6] << 8) |
             (uint64_t)preprocessed[offset + 8 * i + 7];
    }

    // extend 16 words to w[16..79]
    for (int i = 16; i < 80; i++) {
      uint64_t s0 = ((w[i - 15] >> 1) | (w[i - 15] << 63)) ^
                    ((w[i - 15] >> 8) | (w[i - 15] << 56)) ^ (w[i - 15] >> 7);
      uint64_t s1 = ((w[i - 2] >> 19) | (w[i - 2] << 45)) ^
                    ((w[i - 2] >> 61) | (w[i - 2] << 3)) ^ (w[i - 2] >> 6);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = H[0];
    uint64_t b = H[1];
    uint64_t c = H[2];
    uint64_t d = H[3];
    uint64_t e = H[4];
    uint64_t f = H[5];
    uint64_t g = H[6];
    uint64_t h = H[7];

    // compression main loop
    for (int i = 0; i < 80; i++) {
      uint64_t s1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^
                    ((e >> 41) | (e << 23));
      uint64_t ch = (e & f) ^ ((~e) & g);
      uint64_t temp1 = h + s1 + ch + sha512_k[i] + w[i];
      uint64_t s0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^
                    ((a >> 39) | (a << 25));
      uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint64_t temp2 = s0 + maj;

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
    for (int j = 0; j < 8; j++) {
      // big endian
      output[8 * i + j] = (H[i] >> (8 * (7 - j))) & 0xFF;
    }
  }
}

void sha384(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  uint64_t H[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
                   0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
                   0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

  sha384_512(input, output, H);
  // 384
  output.resize(48);
}
void sha512(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  uint64_t H[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
                   0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                   0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

  sha384_512(input, output, H);
}