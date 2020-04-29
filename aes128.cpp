#include "crypto.h"
#include <cassert>
#include <vector>

using namespace std;

// reference:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
// https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf

// S-box(Figure 7)
const uint32_t s[] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16};

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
inline uint8_t mul2(uint8_t input) {
  uint8_t output;
  output = input << 1;
  if (input & 0x80) {
    // handle modulo
    output ^= 0b00011011;
  }
  return output;
}

inline uint8_t mul3(uint8_t input) {
  uint8_t input2 = mul2(input);
  uint8_t output = input2 ^ input;
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

inline void sub_bytes(uint8_t state[16]) {
  for (int i = 0; i < 16; i++) {
    state[i] = s[state[i]];
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
        uint8_t new0 = mul2(state[i * 4]) ^ mul3(state[i * 4 + 1]) ^
                       state[i * 4 + 2] ^ state[i * 4 + 3];
        // 1 2 3 1
        uint8_t new1 = state[i * 4] ^ mul2(state[i * 4 + 1]) ^
                       mul3(state[i * 4 + 2]) ^ state[i * 4 + 3];
        // 1 1 2 3
        uint8_t new2 = state[i * 4] ^ state[i * 4 + 1] ^
                       mul2(state[i * 4 + 2]) ^ mul3(state[i * 4 + 3]);
        // 3 1 1 2
        uint8_t new3 = mul3(state[i * 4]) ^ state[i * 4 + 1] ^
                       state[i * 4 + 2] ^ mul2(state[i * 4 + 3]);
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
    }
  }
}