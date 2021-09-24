#include "crypto.h"
#include "util.h"
#include <assert.h>
#include <string.h>
#include <string>
#include <vector>

// reference:
// https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf
// https://datatracker.ietf.org/doc/html/rfc1320
// https://rosettacode.org/wiki/MD4#C

// #define DEBUG
#ifdef DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

struct ValueLog {
  union {
    struct {
      uint32_t A;
      uint32_t B;
      uint32_t C;
      uint32_t D;
    };
    uint32_t values[4];
  };
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
#define LEFTROTATE(A, N) (((A) << (N)) | ((A) >> (32 - (N))))

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
#define SAVELOG                                                                \
  do {                                                                         \
    ValueLog log;                                                              \
    log.A = A;                                                                 \
    log.B = B;                                                                 \
    log.C = C;                                                                 \
    log.D = D;                                                                 \
    res.push_back(log);                                                        \
  } while (0);

    SAVELOG;

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

  hash.A = A;
  hash.B = B;
  hash.C = C;
  hash.D = D;

  return res;
}

std::vector<ValueLog> md4_dump_words(const std::vector<uint32_t> &words1) {
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

  dprintf("Variables:\n");
  for (size_t i = 0; i < log1.size(); i++) {
    dprintf("%02zu: A=%08x B=%08x C=%08x D=%08x", i, log1[i].A, log1[i].B,
            log1[i].C, log1[i].D);
    if (memcmp(&log1[i], &log2[i], sizeof(ValueLog)) == 0) {
      dprintf(" identical\n");
    } else {
      dprintf(" diff A=%08x B=%08x C=%08x D=%08x\n", log2[i].A - log1[i].A,
              log2[i].B - log1[i].B, log2[i].C - log1[i].C,
              log2[i].D - log1[i].D);
    }
  }
  dprintf("Hash1: A=%08x B=%08x C=%08x D=%08x\n", hash1.A, hash1.B, hash1.C,
          hash1.D);
  dprintf("Hash2: A=%08x B=%08x C=%08x D=%08x\n", hash2.A, hash2.B, hash2.C,
          hash2.D);

  if (memcmp(&hash1, &hash2, sizeof(ValueLog)) == 0) {
    printf("Found collision!\n");
    exit(0);
  }
  return log1;
}

void md4_dump(const std::vector<uint8_t> &m1) {
  std::vector<uint8_t> preprocessed1 = padding(m1);
  std::vector<uint32_t> words1 = unpack_uint32_le(preprocessed1);
  md4_dump_words(words1);
}

struct Constraint {
  enum { BIT_MATCH, SET, CLEAR } ty;
  uint32_t offset;
  // a, b, c, d
  uint32_t value_index;
  // a1, a2, a3, a4
  uint32_t row_index;
};

std::vector<Constraint> parse_constraint(const std::string &s) {
  size_t from_pos = 0;
  size_t to_pos = 0;
  std::vector<Constraint> res;
  while (from_pos < s.size()) {
    to_pos = s.find(';', from_pos);
    if (to_pos == std::string::npos) {
      to_pos = s.size();
    }
    std::string part = s.substr(from_pos, to_pos - from_pos);
    uint32_t offset;
    char ch;
    uint32_t index;
    sscanf(part.c_str(), "%c%d,%d", &ch, &index, &offset);

    size_t eq = part.find('=');
    assert(eq != std::string::npos);

    if (part[eq + 1] == '1') {
      res.push_back(Constraint{.ty = Constraint::SET, .offset = offset});
    } else if (part[eq + 1] == '0') {
      res.push_back(Constraint{.ty = Constraint::CLEAR, .offset = offset});
    } else {
      sscanf(&part.c_str()[eq + 1], "%c%d,%d", &ch, &index, &offset);
      uint32_t value_index = ch - 'a';
      assert(value_index <= 3);
      res.push_back(Constraint{
          .ty = Constraint::BIT_MATCH,
          .offset = offset,
          .value_index = value_index,
          .row_index = index,
      });
    }

    from_pos = to_pos + 1;
  }
  return res;
}

void single_step_modification(const std::vector<uint32_t> &input) {
  dprintf("Before modification:\n");
  std::vector<uint32_t> words = input;
  std::vector<ValueLog> log = md4_dump_words(words);

  // To satisfy Table 6, we can construct m0 to m15 to meet the constraints for
  // a1 to d4. But from a5, the m should be updated by multi step modification.

  // note: bit starts from 1 to 32
#define EXTRACT_BIT(num, bit) (((num) >> (bit - 1)) & 0x1)
#define EXTRACT(num, bit) ((num) & (0x1 << (bit - 1)))
#define EXTRACT_NEG(num, bit) ((~num) & (0x1 << (bit - 1)))
#define RIGHTROTATE(A, N) (((A) >> (N)) | ((A) << (32 - (N))))

// remove duplicate code
// read from log
#define VARS                                                                   \
  uint32_t a0 = log[0].A;                                                      \
  uint32_t b0 = log[0].B;                                                      \
  uint32_t c0 = log[0].C;                                                      \
  uint32_t d0 = log[0].D;                                                      \
  uint32_t a1 = log[4].A;                                                      \
  uint32_t b1 = log[4].B;                                                      \
  uint32_t c1 = log[4].C;                                                      \
  uint32_t d1 = log[4].D;                                                      \
  uint32_t a2 = log[8].A;                                                      \
  uint32_t b2 = log[8].B;                                                      \
  uint32_t c2 = log[8].C;                                                      \
  uint32_t d2 = log[8].D;                                                      \
  uint32_t a3 = log[12].A;                                                     \
  uint32_t b3 = log[12].B;                                                     \
  uint32_t c3 = log[12].C;                                                     \
  uint32_t d3 = log[12].D;

  std::vector<std::vector<Constraint>> constraints;
  constraints.push_back(parse_constraint("a1,7=b0,7"));
  constraints.push_back(parse_constraint("d1,7=0;d1,8=a1,8;d1,11=a1,11"));
  constraints.push_back(parse_constraint("c1,7=1;c1,8=1;c1,11=0;c1,26=d1,26"));
  constraints.push_back(parse_constraint("b1,7=1;b1,8=0;b1,11=0;b1,26=0"));
  constraints.push_back(parse_constraint("a2,8=1;a2,11=1;a2,26=0;a2,24=b1,14"));
  constraints.push_back(parse_constraint(
      "d2,14=0;d2,19=a2,19;d2,20=a2,20;d2,21=a2,21;d2,22=a2,22;d2,26=1"));
  constraints.push_back(parse_constraint(
      "c2,13=d2,13;c2,14=0;c2,15=d2,15;c2,19=0;c2,20=0;c2,21=1;c2,22=0"));
  constraints.push_back(parse_constraint(
      "b2,13=1;b2,14=1;b2,15=0;b2,17=c2,17;b2,19=0;b2,20=0;b2,21=0;b2,22=0"));
  constraints.push_back(
      parse_constraint("a3,13=1;a3,14=1;a3,15=1;a3,17=0;a3,19=0;a3,20=0;a3,21="
                       "0;a3,23=b2,23;a3,22=1;a3,26=b2,26"));
  constraints.push_back(
      parse_constraint("d3,13=1;d3,14=1;d3,15=1;d3,17=0;d3,20=0;d3,21=1;d3,22="
                       "1;d3,23=0;d3,26=1;d3,30=a3,30"));
  constraints.push_back(parse_constraint(
      "c3,17=1;c3,20=0;c3,21=0;c3,22=0;c3,23=0;c3,26=0;c3,30=1;c3,32=d3,32"));
  constraints.push_back(parse_constraint(
      "b3,20=0;b3,21=1;b3,22=1;b3,23=c3,23;b3,26=1;b3,30=0;b3,32=0"));
  constraints.push_back(parse_constraint(
      "a4,23=0;a4,26=0;a4,27=b3,27;a4,29=b3,29;a4,30=1;a4,32=0"));
  constraints.push_back(
      parse_constraint("d4,23=0;d4,26=0;d4,27=1;d4,29=1;d4,30=0,d4;32=1"));
  constraints.push_back(
      parse_constraint("c4,19=d4,19;c4,23=1;c4,26=1;c4,27=0;c4,29=0;c4,30=0"));
  constraints.push_back(
      parse_constraint("b4,19=0;b4,26=c4,26;b4,27=1;b4,29=1;b4,30=0"));

  for (size_t i = 0; i < constraints.size(); i++) {
    // a, d, c, b
    int order[4] = {0, 3, 2, 1};
    int value_index = order[i % 4];
    // a1, a2, a3, a4
    int row_index = i / 4 + 1;

    uint32_t target_value = log[row_index * 4].values[value_index];

    std::vector<Constraint> &constrs = constraints[i];
    for (auto c : constrs) {
      if (c.ty == Constraint::SET) {
        target_value ^= EXTRACT_NEG(target_value, c.offset);
      } else if (c.ty == Constraint::CLEAR) {
        target_value ^= EXTRACT(target_value, c.offset);
      } else if (c.ty == Constraint::BIT_MATCH) {
        uint32_t prev_value = log[c.row_index * 4].values[c.value_index];
        target_value ^= EXTRACT(target_value ^ prev_value, c.offset);
      } else {
        assert(false);
      }
    }

    ValueLog &cur = log[row_index * 4];
    ValueLog &pre = log[(row_index - 1) * 4];
    if (i % 4 == 0) {
      // a
      words[i] = RIGHTROTATE(target_value, 3) - pre.A - F(pre.B, pre.C, pre.D);
    } else if (i % 4 == 1) {
      // d
      words[i] = RIGHTROTATE(target_value, 7) - pre.D - F(cur.A, pre.B, pre.C);
    } else if (i % 4 == 2) {
      // c
      words[i] = RIGHTROTATE(target_value, 11) - pre.C - F(cur.D, cur.A, pre.B);
    } else if (i % 4 == 3) {
      // b
      words[i] = RIGHTROTATE(target_value, 19) - pre.B - F(cur.C, cur.D, cur.A);
    }
    log = md4_dump_words(words);
  }

  // direct way
  /*
    if (1) {
      VARS;

      // a1,7 = b0,7
      a1 = a1 ^ (EXTRACT(a1, 7) ^ EXTRACT(b0, 7));
      words[0] = RIGHTROTATE(a1, 3) - a0 - F(b0, c0, d0);
      dprintf("After modification for step 1:\n");
      log = md4_dump_words(words);
    }

  if (1) {
    VARS;

    // d1,7 = 0; d1,8 = a1,8; d1,11 = a1,11
    d1 = d1 ^ EXTRACT(d1, 7) ^ (EXTRACT(d1, 8) ^ EXTRACT(a1, 8)) ^
         (EXTRACT(d1, 11) ^ EXTRACT(a1, 11));
    words[1] = RIGHTROTATE(d1, 7) - d0 - F(a1, b0, c0);
    dprintf("After modification for step 2:\n");
    log = md4_dump_words(words);
  }

  if (1) {
    VARS;

    // c1,7=1; c1,8=1; c1,11=0; c1,26=d1,26
    c1 = c1 ^ EXTRACT_NEG(c1, 7) ^ EXTRACT_NEG(c1, 8) ^ EXTRACT(c1, 11) ^
         (EXTRACT(c1, 26) ^ EXTRACT(d1, 26));
    words[2] = RIGHTROTATE(c1, 11) - c0 - F(d1, a1, b0);
    dprintf("After modification for step 3:\n");
    log = md4_dump_words(words);
    words = words;
  }

  if (1) {
    VARS;

    // b1,7=1; b1,8=0; b1,11=0; b1,26=0
    b1 = b1 ^ EXTRACT_NEG(b1, 7) ^ EXTRACT(b1, 8) ^ EXTRACT(b1, 11) ^
         EXTRACT(b1, 26);
    words[3] = RIGHTROTATE(b1, 19) - b0 - F(c1, d1, a1);
    dprintf("After modification for step 4:\n");
    log = md4_dump_words(words);
  }

  if (1) {
    VARS;

    // a2,8=1;a2,11=1;a2,26=0;a2,24=b1,14
    a2 = a2 ^ EXTRACT_NEG(a2, 8) ^ EXTRACT_NEG(a2, 11) ^ EXTRACT(a2, 26) ^
         (EXTRACT(a2, 14) ^ EXTRACT(b1, 14));
    words[4] = RIGHTROTATE(a2, 3) - a1 - F(b1, c1, d1);
    dprintf("After modification for step 5:\n");
    log = md4_dump_words(words);
  }

  if (1) {
    VARS;

    // d2,14=0; d2,19=a2,19; d2,20=a2,20; d2,21=a2,21; d2,22=a2,22; d2,26=1
    d2 = d2 ^ EXTRACT(d2, 14) ^ (EXTRACT(d2, 19) ^ EXTRACT(a2, 19)) ^
         (EXTRACT(d2, 20) ^ EXTRACT(a2, 20)) ^
         (EXTRACT(d2, 21) ^ EXTRACT(a2, 21)) ^
         (EXTRACT(d2, 22) ^ EXTRACT(a2, 22)) ^ EXTRACT_NEG(d2, 26);
    words[5] = RIGHTROTATE(d2, 7) - d1 - F(a2, b1, c1);
    dprintf("After modification for step 6:\n");
    log = md4_dump_words(words);
  }

  if (1) {
    VARS;

    // c2,13=d2,13; c2,14=0; c2,15=d2,15; c2,19=0; c2,20=0; c2,21=1; c2,22=0
    c2 = c2 ^ (EXTRACT(c2, 13) ^ EXTRACT(d2, 13)) ^ EXTRACT(c2, 14) ^
         (EXTRACT(c2, 15) ^ EXTRACT(d2, 15)) ^ EXTRACT(c2, 19) ^
         EXTRACT(c2, 20) ^ EXTRACT_NEG(c2, 21) ^ EXTRACT(c2, 22);
    words[6] = RIGHTROTATE(c2, 11) - c1 - F(d2, a2, b1);
    dprintf("After modification for step 7:\n");
    log = md4_dump_words(words);
  }

  if (1) {
    VARS;

    // b2,13=1; b2,14=1; b2,15=0; b2,17=c2,17; b2,19=0; b2,20=0; b2,21=0;
    // b2,22=0
    b2 = b2 ^ EXTRACT_NEG(b2, 13) ^ EXTRACT_NEG(b2, 14) ^ EXTRACT(b2, 15) ^
         (EXTRACT(b2, 17) ^ EXTRACT(c2, 17)) ^ EXTRACT(b2, 19) ^
         EXTRACT(b2, 20) ^ EXTRACT(b2, 21) ^ EXTRACT(b2, 22);
    words[7] = RIGHTROTATE(b2, 19) - b1 - F(c2, d2, a2);
    dprintf("After modification for step 8:\n");
    log = md4_dump_words(words);
  }

  if (1) {
    VARS;

    // a3,13=1; a3,14=1; a3,15=1; a3,17=0; a3,19=0; a3,20=0; a3,21=0;
    // a3,23=b2,23; a3,22=1; a3,26=b2,26
    a3 = a3 ^ EXTRACT_NEG(a3, 13) ^ EXTRACT_NEG(a3, 14) ^ EXTRACT_NEG(a3, 15) ^
         EXTRACT(a3, 17) ^ EXTRACT(a3, 19) ^ EXTRACT(a3, 20) ^ EXTRACT(a3, 21) ^
         (EXTRACT(a3, 23) ^ EXTRACT(b2, 23)) ^ EXTRACT_NEG(a3, 22) ^
         (EXTRACT_NEG(a3, 26) ^ EXTRACT_NEG(b2, 26));
    words[8] = RIGHTROTATE(a3, 3) - a2 - F(b2, c2, d2);
    dprintf("After modification for step 9:\n");
    log = md4_dump_words(words);
  }
    */

  if (1) {
    // check
    VARS;

    // a1
    assert(EXTRACT(a1, 7) == EXTRACT(b0, 7));
    // d1
    assert(EXTRACT(d1, 7) == 0);
    assert(EXTRACT(d1, 8) == EXTRACT(a1, 8));
    assert(EXTRACT(d1, 11) == EXTRACT(a1, 11));
    // c1
    assert(EXTRACT(c1, 7) != 0);
    assert(EXTRACT(c1, 8) != 0);
    assert(EXTRACT(c1, 11) == 0);
    assert(EXTRACT(c1, 26) == EXTRACT(d1, 26));
    // b1
    assert(EXTRACT(b1, 7) != 0);
    assert(EXTRACT(b1, 8) == 0);
    assert(EXTRACT(b1, 11) == 0);
    assert(EXTRACT(b1, 26) == 0);
    // a2
    assert(EXTRACT(a2, 8) != 0);
    assert(EXTRACT(a2, 11) != 0);
    assert(EXTRACT(a2, 26) == 0);
    assert(EXTRACT(a2, 14) == EXTRACT(b1, 14));
    // d2
    assert(EXTRACT(d2, 14) == 0);
    assert(EXTRACT(d2, 19) == EXTRACT(a2, 19));
    assert(EXTRACT(d2, 20) == EXTRACT(a2, 20));
    assert(EXTRACT(d2, 21) == EXTRACT(a2, 21));
    assert(EXTRACT(d2, 22) == EXTRACT(a2, 22));
    assert(EXTRACT(d2, 26) != 0);
    // c2
    assert(EXTRACT(c2, 13) == EXTRACT(d2, 13));
    assert(EXTRACT(c2, 14) == 0);
    assert(EXTRACT(c2, 15) == EXTRACT(d2, 15));
    assert(EXTRACT(c2, 19) == 0);
    assert(EXTRACT(c2, 20) == 0);
    assert(EXTRACT(c2, 21) != 0);
    assert(EXTRACT(c2, 22) == 0);
    // b2
    assert(EXTRACT(b2, 13) != 0);
    assert(EXTRACT(b2, 14) != 0);
    assert(EXTRACT(b2, 15) == 0);
    assert(EXTRACT(b2, 17) == EXTRACT(c2, 17));
    assert(EXTRACT(b2, 19) == 0);
    assert(EXTRACT(b2, 20) == 0);
    assert(EXTRACT(b2, 21) == 0);
    assert(EXTRACT(b2, 22) == 0);
    // a3
    assert(EXTRACT(a3, 13) != 0);
    assert(EXTRACT(a3, 14) != 0);
    assert(EXTRACT(a3, 15) != 0);
    assert(EXTRACT(a3, 17) == 0);
    assert(EXTRACT(a3, 19) == 0);
    assert(EXTRACT(a3, 20) == 0);
    assert(EXTRACT(a3, 21) == 0);
    assert(EXTRACT(a3, 23) == EXTRACT(b2, 23));
    assert(EXTRACT(a3, 22) != 0);
    assert(EXTRACT(a3, 26) == EXTRACT(b2, 26));
  }
}

int main(int argc, char *argv[]) {
  // valid collision
  if (0) {
    md4_dump(parse_hex_new(
        "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f"
        "5d2a3bb3719dc6"
        "9891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9"));
  }

  // testing collision
  if (0) {
    std::vector<uint8_t> input;
    for (int i = 0; i < 64; i++) {
      input.push_back(i);
    }
    single_step_modification(unpack_uint32_le(input));
  }

  // finding collision
  if (1) {
    std::vector<uint8_t> input;
    input.resize(64);

    uint64_t begin = get_time_us();
    int tries = 1000000;
    for (int i = 0; i < tries; i++) {
      for (int j = 0; j < 64; j++) {
        input[j] = rand();
      }
      single_step_modification(unpack_uint32_le(input));
    }
    uint64_t elapsed = get_time_us() - begin;
    printf("%lf mod/s, elapsed %2lf s\n", 1000000.0 * tries / elapsed,
           elapsed / 1000000.0);
  }
  return 0;
}