#include "crypto.h"

// reference:
// https://datatracker.ietf.org/doc/html/rfc1320
// https://rosettacode.org/wiki/MD4#C

void md4(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  // 128 bits = 16 bytes
  output.resize(16);

  // preprocessing
  uint64_t length = input.size();
  // 9: 8-byte length + 0x80
  // padding: 80 00 00 00 ... [64-bit length]
  size_t real_length = (length + 9 + 63) & ~63;
  std::vector<uint8_t> preprocessed = input;
  preprocessed.resize(real_length);
  preprocessed[length] = 0x80;
  // little endian
  for (int i = 0; i < 8; i++) {
    preprocessed[real_length - i - 1] = ((length * 8) >> (8 * (7 - i))) & 0xFF;
  }

  uint32_t A = 0x67452301;
  uint32_t B = 0xefcdab89;
  uint32_t C = 0x98badcfe;
  uint32_t D = 0x10325476;
  uint32_t AA, BB, CC, DD;
  for (size_t offset = 0; offset < real_length; offset += 64) {
    // big endian 01-ef, ef-10

// F(X,Y,Z) = XY v not(X) Z
#define F(X, Y, Z) (((X) & (Y)) | ((~(X)) & (Z)))
// G(X,Y,Z) = XY v XZ v YZ
#define G(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
// H(X,Y,Z) = X xor Y xor Z
#define H(X, Y, Z) ((X) ^ (Y) ^ (Z))
// cyclic rotate
#define LEFTROTATE(A, N) ((A) << (N)) | ((A) >> (32 - (N)))

    uint32_t X[16];

    // copy preprocessed to x[0..15]
    // little endian
    for (int i = 0; i < 16; i++) {
      X[i] = ((uint32_t)preprocessed[offset + 4 * i + 3] << 24) |
             ((uint32_t)preprocessed[offset + 4 * i + 2] << 16) |
             ((uint32_t)preprocessed[offset + 4 * i + 1] << 8) |
             (uint32_t)preprocessed[offset + 4 * i + 0];
    }

    // save
    AA = A;
    BB = B;
    CC = C;
    DD = D;

    // round 1
    /* Let [abcd k s] denote the operation
             a = (a + F(b,c,d) + X[k]) <<< s. */
#define MD4ROUND1(a, b, c, d, x, s)                                            \
  a += F(b, c, d) + x;                                                         \
  a = LEFTROTATE(a, s);

    MD4ROUND1(A, B, C, D, X[0], 3);
    MD4ROUND1(D, A, B, C, X[1], 7);
    MD4ROUND1(C, D, A, B, X[2], 11);
    MD4ROUND1(B, C, D, A, X[3], 19);
    MD4ROUND1(A, B, C, D, X[4], 3);
    MD4ROUND1(D, A, B, C, X[5], 7);
    MD4ROUND1(C, D, A, B, X[6], 11);
    MD4ROUND1(B, C, D, A, X[7], 19);
    MD4ROUND1(A, B, C, D, X[8], 3);
    MD4ROUND1(D, A, B, C, X[9], 7);
    MD4ROUND1(C, D, A, B, X[10], 11);
    MD4ROUND1(B, C, D, A, X[11], 19);
    MD4ROUND1(A, B, C, D, X[12], 3);
    MD4ROUND1(D, A, B, C, X[13], 7);
    MD4ROUND1(C, D, A, B, X[14], 11);
    MD4ROUND1(B, C, D, A, X[15], 19);

    /* Round 2. */
    /* Let [abcd k s] denote the operation
         a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. */
#define MD4ROUND2(a, b, c, d, x, s)                                            \
  a += G(b, c, d) + x + (uint32_t)0x5A827999;                                  \
  a = LEFTROTATE(a, s);
    MD4ROUND2(A, B, C, D, X[0], 3);
    MD4ROUND2(D, A, B, C, X[4], 5);
    MD4ROUND2(C, D, A, B, X[8], 9);
    MD4ROUND2(B, C, D, A, X[12], 13);
    MD4ROUND2(A, B, C, D, X[1], 3);
    MD4ROUND2(D, A, B, C, X[5], 5);
    MD4ROUND2(C, D, A, B, X[9], 9);
    MD4ROUND2(B, C, D, A, X[13], 13);
    MD4ROUND2(A, B, C, D, X[2], 3);
    MD4ROUND2(D, A, B, C, X[6], 5);
    MD4ROUND2(C, D, A, B, X[10], 9);
    MD4ROUND2(B, C, D, A, X[14], 13);
    MD4ROUND2(A, B, C, D, X[3], 3);
    MD4ROUND2(D, A, B, C, X[7], 5);
    MD4ROUND2(C, D, A, B, X[11], 9);
    MD4ROUND2(B, C, D, A, X[15], 13);

    /* Round 3. */
    /* Let [abcd k s] denote the operation
         a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s. */
#define MD4ROUND3(a, b, c, d, x, s)                                            \
  a += H(b, c, d) + x + (uint32_t)0x6ED9EBA1;                                  \
  a = LEFTROTATE(a, s);
    MD4ROUND3(A, B, C, D, X[0], 3);
    MD4ROUND3(D, A, B, C, X[8], 9);
    MD4ROUND3(C, D, A, B, X[4], 11);
    MD4ROUND3(B, C, D, A, X[12], 15);
    MD4ROUND3(A, B, C, D, X[2], 3);
    MD4ROUND3(D, A, B, C, X[10], 9);
    MD4ROUND3(C, D, A, B, X[6], 11);
    MD4ROUND3(B, C, D, A, X[14], 15);
    MD4ROUND3(A, B, C, D, X[1], 3);
    MD4ROUND3(D, A, B, C, X[9], 9);
    MD4ROUND3(C, D, A, B, X[5], 11);
    MD4ROUND3(B, C, D, A, X[13], 15);
    MD4ROUND3(A, B, C, D, X[3], 3);
    MD4ROUND3(D, A, B, C, X[11], 9);
    MD4ROUND3(C, D, A, B, X[7], 11);
    MD4ROUND3(B, C, D, A, X[15], 15);

    A += AA;
    B += BB;
    C += CC;
    D += DD;
  }

  uint32_t H[4] = {A, B, C, D};
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      // little endian
      output[4 * i + j] = (H[i] >> (8 * j)) & 0xFF;
    }
  }
}