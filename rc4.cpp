#include "crypto.h"
#include <cassert>

void rc4(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key,
         std::vector<uint8_t> &output) {
  assert(key.size() >= 0 && key.size() <= 256);
  output.resize(input.size());

  // key scheduling
  uint8_t s[256];
  for (int i = 0; i < 256; i++) {
    s[i] = i;
  }
  int j = 0;
  for (int i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.size()]) % 256;
    uint8_t temp = s[i];
    s[i] = s[j];
    s[j] = temp;
  }

  // pseudo random generation
  int i = 0;
  j = 0;
  for (int k = 0; k < input.size();k++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    uint8_t temp = s[i];
    s[i] = s[j];
    s[j] = temp;
    uint8_t K = s[(s[i] + s[j]) % 256];
    output[k] = input[k] ^ K;
  }
}
