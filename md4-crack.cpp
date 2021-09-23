#include "crypto.h"
#include "util.h"
#include <string.h>
#include <vector>

// reference:
// https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf
// https://datatracker.ietf.org/doc/html/rfc1320
// https://rosettacode.org/wiki/MD4#C

struct ValueLog {
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;
};

std::vector<uint8_t> padding(const std::vector<uint8_t> &input) {
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
  return preprocessed;
}

std::vector<ValueLog> md4_crack_logging(const std::vector<uint32_t> &input,
                                        struct ValueLog &hash) {
  // save value log
  std::vector<ValueLog> res;

  uint32_t A = 0x67452301;
  uint32_t B = 0xefcdab89;
  uint32_t C = 0x98badcfe;
  uint32_t D = 0x10325476;
  uint32_t AA, BB, CC, DD;
  for (size_t offset = 0; offset < input.size(); offset += 16) {
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
      X[i] = input[offset + i];
    }

    // save
    AA = A;
    BB = B;
    CC = C;
    DD = D;
#define SAVELOG res.push_back(ValueLog{.A = A, .B = B, .C = C, .D = C});

    // round 1
    /* Let [abcd k s] denote the operation
             a = (a + F(b,c,d) + X[k]) <<< s. */
#define MD4ROUND1(a, b, c, d, x, s)                                            \
  a += F(b, c, d) + x;                                                         \
  a = LEFTROTATE(a, s);                                                        \
  SAVELOG;

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
  a = LEFTROTATE(a, s);                                                        \
  SAVELOG;

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
  a = LEFTROTATE(a, s);                                                        \
  SAVELOG;

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

  hash = ValueLog{.A = A, .B = B, .C = C, .D = D};

  return res;
}

void md4_dump(const std::vector<uint8_t> &m1) {
  std::vector<uint8_t> preprocessed1 = padding(m1);
  std::vector<uint32_t> words1 = unpack_uint32_le(preprocessed1);
  ValueLog hash1;
  std::vector<ValueLog> log1 = md4_crack_logging(words1, hash1);
  std::vector<uint32_t> words2 = words1;

  // delta m1 = 2^31
  words2[1] += 0x80000000;
  // delta m2 = 2^31 - 2^28
  words2[2] += 0x80000000 - 0x10000000;
  // delta m12 = -2^16
  words2[12] += -0x00010000;

  ValueLog hash2;
  std::vector<ValueLog> log2 = md4_crack_logging(words2, hash2);

  printf("Variables:\n");
  for (size_t i = 0; i < log1.size(); i++) {
    if (memcmp(&log1[i], &log2[i], sizeof(ValueLog)) == 0) {
      printf("%02zu: identical\n", i);
    } else {
      printf(
          "%02zu: A=%08x B=%08x C=%08x D=%08x A=%08x B=%08x C=%08x D=%08x \n",
          i, log1[i].A, log1[i].B, log1[i].C, log1[i].D, log2[i].A, log2[i].B,
          log2[i].C, log2[i].D);
    }
  }
  printf("Hash1: A=%08x B=%08x C=%08x D=%08x\n", hash1.A, hash1.B, hash1.C,
         hash1.D);
  printf("Hash2: A=%08x B=%08x C=%08x D=%08x\n", hash2.A, hash2.B, hash2.C,
         hash2.D);
}

int main(int argc, char *argv[]) {
  md4_dump(parse_hex_new(
      "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f"
      "5d2a3bb3719dc6"
      "9891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9"));
  /*
parse_hex_new(
"839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb371"
"9dc6"
"9891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9"));
*/
  return 0;
}