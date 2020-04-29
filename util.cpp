#include "util.h"
#include <cassert>

void parse_hex(const std::string &input, std::vector<uint8_t> &output) {
  assert((input.size() % 2) == 0);
  output.resize(input.size() / 2);
  for (int i = 0; i < input.size(); i += 2) {
    output[i / 2] = std::stoi(input.substr(i, 2), 0, 16);
  }
}

std::vector<uint8_t> parse_hex_new(const std::string &input) {
  std::vector<uint8_t> output;
  assert((input.size() % 2) == 0);
  output.resize(input.size() / 2);
  for (int i = 0; i < input.size(); i += 2) {
    output[i / 2] = std::stoi(input.substr(i, 2), 0, 16);
  }
  return output;
}

void random_fill(std::vector<uint8_t> &data) {
  for (int i = 0; i < data.size(); i++) {
    data[i] = rand();
  }
}

void pkcs7_pad(std::vector<uint8_t> &data, size_t block_size) {
  size_t pad = block_size - (data.size() % block_size);
  for (size_t i = 0; i < pad; i++) {
    data.push_back(pad);
  }
}

void pkcs7_unpad(std::vector<uint8_t> &data, size_t block_size) {
  assert(data.size() > 0);
  assert(data.size() % block_size == 0);
  uint8_t pad = data[data.size() - 1];
  assert(pad <= block_size && pad <= data.size());
  data.resize(data.size() - pad);
}