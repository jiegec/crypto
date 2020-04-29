#include "crypto.h"
#include <cassert>
#include <vector>

using namespace std;

// reference:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
// https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf

// S-box(Figure 7)
const uint32_t s[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

// Inverse S-box(Figure 14)
const uint32_t inv_s[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

// Rcon
const uint32_t rcon[] = {0x01000000, 0x02000000, 0x04000000, 0x08000000,
                         0x10000000, 0x20000000, 0x40000000, 0x80000000,
                         0x1B000000, 0x36000000};

inline uint32_t subword(uint32_t input) {
  // apply sbox to each byte
  uint32_t output = 0;
  output |= s[(input >> 24)] << 24;
  output |= s[(input >> 16) & 0xFF] << 16;
  output |= s[(input >> 8) & 0xFF] << 8;
  output |= s[input & 0xFF];
  return output;
}

inline void add_round_key(uint8_t state[16], const uint32_t *roundkey) {
  for (int i = 0; i < 16; i++) {
    // column major order
    state[i] ^= (roundkey[i / 4] >> (8 * (3 - i % 4))) & 0xFF;
  }
}

inline void print_state(const uint8_t state[16]) {
  printf("state:\n");
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      printf("%02x ", state[i + j * 4]);
    }
    printf("\n");
  }
}

// modulo x^8 + x^4 + x^3 + x + 1
// 0b100011011
// (0b1xxxxxxx << 1) ^ 0b100011011
inline uint8_t mul_2(uint8_t input) {
  uint8_t output;
  output = input << 1;
  if (input & 0x80) {
    // handle modulo
    output ^= 0b00011011;
  }
  return output;
}

inline uint8_t mul_3(uint8_t input) {
  uint8_t input2 = mul_2(input);
  uint8_t output = input2 ^ input;
  return output;
}

// 9 = 0b1001
inline uint8_t mul_9(uint8_t input) {
  uint8_t input2 = mul_2(input);
  uint8_t input4 = mul_2(input2);
  uint8_t input8 = mul_2(input4);
  uint8_t output = input8 ^ input;
  return output;
}

// b = 0b1011
inline uint8_t mul_b(uint8_t input) {
  uint8_t input2 = mul_2(input);
  uint8_t input4 = mul_2(input2);
  uint8_t input8 = mul_2(input4);
  uint8_t output = input8 ^ input2 ^ input;
  return output;
}

// d = 0b1101
inline uint8_t mul_d(uint8_t input) {
  uint8_t input2 = mul_2(input);
  uint8_t input4 = mul_2(input2);
  uint8_t input8 = mul_2(input4);
  uint8_t output = input8 ^ input4 ^ input;
  return output;
}

// e = 0b1110
inline uint8_t mul_e(uint8_t input) {
  uint8_t input2 = mul_2(input);
  uint8_t input4 = mul_2(input2);
  uint8_t input8 = mul_2(input4);
  uint8_t output = input8 ^ input4 ^ input2;
  return output;
}

inline void shift_rows(uint8_t state[16]) {
  // row 2, shift by 1
  uint8_t temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;
  // row 3, shift by 2
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;
  // row 4, shift by 3
  temp = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = state[3];
  state[3] = temp;
}

inline void inv_shift_rows(uint8_t state[16]) {
  // row 2, shift by 1
  uint8_t temp = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = state[1];
  state[1] = temp;
  // row 3, shift by 2
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;
  // row 4, shift by 3
  temp = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = temp;
}

inline void sub_bytes(uint8_t state[16]) {
  for (int i = 0; i < 16; i++) {
    state[i] = s[state[i]];
  }
}

inline void inv_sub_bytes(uint8_t state[16]) {
  for (int i = 0; i < 16; i++) {
    state[i] = inv_s[state[i]];
  }
}

void aes128_cbc_encrypt(const vector<uint8_t> &input,
                        const vector<uint8_t> &key, const vector<uint8_t> &iv,
                        vector<uint8_t> &output) {
  // key expansion
  // aes128: 10 rounds
  // 10+1 roundkeys
  // roundkey = 4 uint32_t
  uint32_t roundkeys[(10 + 1) * 4];

  // init round
  for (int i = 0; i < 4; i++) {
    roundkeys[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
                   (key[4 * i + 2] << 8) | (key[4 * i + 3]);
  }

  // Nk = 4, Nr = 10
  for (int i = 4; i < 4 * (10 + 1); i++) {
    uint32_t temp = roundkeys[i - 1];
    if (i % 4 == 0) {
      // temp = SubWord(RotWord(temp)) xor Rcon(i/Nk)
      uint32_t rotword = (temp << 8) | (temp >> 24);
      temp = subword(rotword) ^ rcon[i / 4 - 1];
    }
    roundkeys[i] = roundkeys[i - 4] ^ temp;
  }

  uint8_t cur_iv[16];
  memcpy(cur_iv, &iv[0], 16);

  // for each block
  for (int offset = 0; offset < input.size(); offset += 16) {
    // column major
    // 0 4 8 12
    // 1 5 9 13
    // 2 6 10 14
    // 3 7 11 15
    uint8_t state[16];

    // state = in
    for (int i = 0; i < 16; i++) {
      state[i] = input[offset + i] ^ cur_iv[i];
    }

    // AddRoundKey(state, w[0, Nb-1])
    add_round_key(state, &roundkeys[0]);

    // 9 rounds
    for (int round = 1; round <= 10 - 1; round++) {
      // SubBytes(state)
      sub_bytes(state);

      // ShiftRows(state)
      shift_rows(state);

      // MixColumns()
      // for 4 columns
      for (int i = 0; i < 4; i++) {
        // 2 3 1 1
        uint8_t new0 = mul_2(state[i * 4]) ^ mul_3(state[i * 4 + 1]) ^
                       state[i * 4 + 2] ^ state[i * 4 + 3];
        // 1 2 3 1
        uint8_t new1 = state[i * 4] ^ mul_2(state[i * 4 + 1]) ^
                       mul_3(state[i * 4 + 2]) ^ state[i * 4 + 3];
        // 1 1 2 3
        uint8_t new2 = state[i * 4] ^ state[i * 4 + 1] ^
                       mul_2(state[i * 4 + 2]) ^ mul_3(state[i * 4 + 3]);
        // 3 1 1 2
        uint8_t new3 = mul_3(state[i * 4]) ^ state[i * 4 + 1] ^
                       state[i * 4 + 2] ^ mul_2(state[i * 4 + 3]);
        state[i * 4] = new0;
        state[i * 4 + 1] = new1;
        state[i * 4 + 2] = new2;
        state[i * 4 + 3] = new3;
      }

      // AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
      add_round_key(state, &roundkeys[round * 4]);
    }

    // SubBytes(state)
    sub_bytes(state);

    // ShiftRows(state)
    shift_rows(state);

    // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    add_round_key(state, &roundkeys[10 * 4]);

    // out = state
    for (int i = 0; i < 16; i++) {
      output[offset + i] = state[i];
      cur_iv[i] = state[i];
    }
  }
}

void aes128_cbc_decrypt(const vector<uint8_t> &input,
                        const vector<uint8_t> &key, const vector<uint8_t> &iv,
                        vector<uint8_t> &output) {
  // key expansion
  // aes128: 10 rounds
  // 10+1 roundkeys
  // roundkey = 4 uint32_t
  uint32_t roundkeys[(10 + 1) * 4];

  // init round
  for (int i = 0; i < 4; i++) {
    roundkeys[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
                   (key[4 * i + 2] << 8) | (key[4 * i + 3]);
  }

  // Nk = 4, Nr = 10
  for (int i = 4; i < 4 * (10 + 1); i++) {
    uint32_t temp = roundkeys[i - 1];
    if (i % 4 == 0) {
      // temp = SubWord(RotWord(temp)) xor Rcon(i/Nk)
      uint32_t rotword = (temp << 8) | (temp >> 24);
      temp = subword(rotword) ^ rcon[i / 4 - 1];
    }
    roundkeys[i] = roundkeys[i - 4] ^ temp;
  }

  uint8_t cur_iv[16];
  memcpy(cur_iv, &iv[0], 16);

  // for each block
  for (int offset = 0; offset < input.size(); offset += 16) {
    // column major
    // 0 4 8 12
    // 1 5 9 13
    // 2 6 10 14
    // 3 7 11 15
    uint8_t state[16];

    // state = in
    for (int i = 0; i < 16; i++) {
      state[i] = input[offset + i];
    }

    // AddRoundKey(state, w[Nr * Nb, (Nr + 1) * Nb - 1])
    add_round_key(state, &roundkeys[10 * 4]);

    // 9 rounds
    for (int round = 10 - 1; round >= 1; round--) {
      // InvShiftRows(state)
      inv_shift_rows(state);

      // InvSubBytes(state)
      inv_sub_bytes(state);

      // AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
      add_round_key(state, &roundkeys[round * 4]);

      // InvMixColumns()
      // for 4 columns
      for (int i = 0; i < 4; i++) {
        // e b d 9
        uint8_t new0 = mul_e(state[i * 4]) ^ mul_b(state[i * 4 + 1]) ^
                       mul_d(state[i * 4 + 2]) ^ mul_9(state[i * 4 + 3]);
        // 9 e b d
        uint8_t new1 = mul_9(state[i * 4]) ^ mul_e(state[i * 4 + 1]) ^
                       mul_b(state[i * 4 + 2]) ^ mul_d(state[i * 4 + 3]);
        // d 9 e b
        uint8_t new2 = mul_d(state[i * 4]) ^ mul_9(state[i * 4 + 1]) ^
                       mul_e(state[i * 4 + 2]) ^ mul_b(state[i * 4 + 3]);
        // b d 9 e
        uint8_t new3 = mul_b(state[i * 4]) ^ mul_d(state[i * 4 + 1]) ^
                       mul_9(state[i * 4 + 2]) ^ mul_e(state[i * 4 + 3]);
        state[i * 4] = new0;
        state[i * 4 + 1] = new1;
        state[i * 4 + 2] = new2;
        state[i * 4 + 3] = new3;
      }
    }

    // InvShiftRows(state)
    inv_shift_rows(state);

    // InvSubBytes(state)
    inv_sub_bytes(state);

    // AddRoundKey(state, w[0, Nb-1])
    add_round_key(state, &roundkeys[0]);

    // out = state
    for (int i = 0; i < 16; i++) {
      output[offset + i] = state[i] ^ cur_iv[i];
      cur_iv[i] = input[offset + i];
    }
  }
}

void aes128_cbc(bool encrypt, const vector<uint8_t> &input,
                const vector<uint8_t> &key, const vector<uint8_t> &iv,
                vector<uint8_t> &output) {
  // block size = 16 bytes
  assert(iv.size() == 16);
  assert((input.size() % 16) == 0);
  output.resize(input.size());
  // key size = 16 bytes
  assert(key.size() == 16);

  if (encrypt) {
    aes128_cbc_encrypt(input, key, iv, output);
  } else {
    aes128_cbc_decrypt(input, key, iv, output);
  }
}
