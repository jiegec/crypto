#include "crypto.h"

// reference:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf

// round constants rc(t)
// taken from OpenSSL iotas[]
const uint64_t rc[] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

template <int d>
void sha3(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  // KECCAK[c] (N, d) = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600 – c] (N, d).
  // N = M || 01
  // SPONGE[f, pad, r](N, d)
  const int c = d * 2;
  const int r = 1600 - c;
  const int block_size = r / 8;
  // KECCAK-p[b, nr]
  const int b = 1600;
  const int nr = 24;
  output.resize(d / 8);

  std::vector<uint8_t> padded = input;
  // padding: 0x06 0x00 .... 0x80 or 0x86
  // align up to multiples of block_size
  size_t real_length =
      (padded.size() + 1 + block_size - 1) / block_size * block_size;
  padded.push_back(0x06);
  padded.resize(real_length);
  padded[real_length - 1] |= 0x80;

  // b-bit width state
  // 5x5 64bit integers
  // w=64
  uint64_t S[b / 64] = {0};

  // for each block
  for (size_t offset = 0; offset < real_length; offset += block_size) {
    // xor into S
    for (int i = 0; i < block_size / 8; i++) {
      // little endian
      S[i] ^= (uint64_t)padded[offset + 8 * i + 0] |
              ((uint64_t)padded[offset + 8 * i + 1] << 8) |
              ((uint64_t)padded[offset + 8 * i + 2] << 16) |
              ((uint64_t)padded[offset + 8 * i + 3] << 24) |
              ((uint64_t)padded[offset + 8 * i + 4] << 32) |
              ((uint64_t)padded[offset + 8 * i + 5] << 40) |
              ((uint64_t)padded[offset + 8 * i + 6] << 48) |
              ((uint64_t)padded[offset + 8 * i + 7] << 56);
    }

    for (int round = 0; round < nr; round++) {
      // ir = 12 + 2l – nr + round
      // A = Rnd(A,ir)
      // A[x, y] = S[x+y*5]

      // theta
      // C[x,z]=A[x,0,z] ⊕ A[x,1,z] ⊕ A[x,2,z] ⊕ A[x,3,z] ⊕ A[x,4,z].
      uint64_t C[5];
      for (int i = 0; i < 5; i++) {
        C[i] = S[i] ^ S[i + 5] ^ S[i + 10] ^ S[i + 15] ^ S[i + 20];
      }
      // D[x, z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z-1) mod w]
      uint64_t D[5];
      for (int i = 0; i < 5; i++) {
        // (z-1) mod w means left rotate
        D[i] =
            C[(i + 4) % 5] ^ ((C[(i + 1) % 5] << 1) | (C[(i + 1) % 5] >> 63));
      }
      // A′[x,y,z] = A[x,y,z] ⊕ D[x,z].
      for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
          S[i + j * 5] ^= D[i];
        }
      }

      // rho
      int x = 1, y = 0;
      for (int t = 0; t <= 23; t++) {
        int rotate = (t + 1) * (t + 2) / 2 % 64;
        S[x + y * 5] =
            (S[x + y * 5] << rotate) | (S[x + y * 5] >> (64 - rotate));
        int new_x = y;
        int new_y = (2 * x + 3 * y) % 5;
        x = new_x;
        y = new_y;
      }

      // pi
      uint64_t S2[b / 64];
      for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
          // A′[x, y, z]= A[(x + 3y) mod 5, x, z].
          S2[i + j * 5] = S[(i + 3 * j) % 5 + i * 5];
        }
      }

      // chi
      for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
          // A′[x,y,z] = A[x,y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5,
          // y,z])
          S[i + j * 5] = S2[i + j * 5] ^
                         ((~S2[(i + 1) % 5 + j * 5]) & S2[(i + 2) % 5 + j * 5]);
        }
      }

      // iota
      S[0] ^= rc[round];
    }
  }

  // output
  for (int i = 0; i < d / 8; i++) {
    output[i] = S[i / 8] >> (8 * (i % 8));
  }
}

void sha3_224(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  sha3<224>(input, output);
}

void sha3_256(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  sha3<256>(input, output);
}

void sha3_384(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  sha3<384>(input, output);
}

void sha3_512(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
  sha3<512>(input, output);
}