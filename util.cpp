#include "util.h"
#include <cassert>
#include <sys/time.h>

void parse_hex(const std::string &input, std::vector<uint8_t> &output) {
  assert((input.size() % 2) == 0);
  output.resize(input.size() / 2);
  for (size_t i = 0; i < input.size(); i += 2) {
    output[i / 2] = std::stoi(input.substr(i, 2), 0, 16);
  }
}

std::vector<uint8_t> parse_hex_new(const std::string &input) {
  std::vector<uint8_t> output;
  assert((input.size() % 2) == 0);
  output.resize(input.size() / 2);
  for (size_t i = 0; i < input.size(); i += 2) {
    output[i / 2] = std::stoi(input.substr(i, 2), 0, 16);
  }
  return output;
}

void random_fill(std::vector<uint8_t> &data) {
  for (size_t i = 0; i < data.size(); i++) {
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

std::vector<uint32_t> unpack_uint32_le(const std::vector<uint8_t> &data) {
  assert(data.size() % 4 == 0);
  std::vector<uint32_t> res;
  res.resize(data.size() / 4);
  for (size_t i = 0; i < res.size(); i++) {
    res[i] = ((uint32_t)data[4 * i + 3] << 24) |
             ((uint32_t)data[4 * i + 2] << 16) |
             ((uint32_t)data[4 * i + 1] << 8) | (uint32_t)data[4 * i + 0];
  }
  return res;
}

uint64_t get_time_us() {
  struct timeval tv = {};
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

void hash_pad(std::vector<uint8_t> &data, bool little_endian, int block_size) {
  uint64_t length = data.size();
  // align up to 64/128 byte blocks
  // 9: 8-byte length + 0x80
  // padding: 80 00 00 00 ... [64-bit length]
  size_t real_length = (length + 9 + (block_size - 1)) & ~(block_size - 1);
  data.resize(real_length);
  data[length] = 0x80;
  if (little_endian) {
    // little endian
    for (int i = 0; i < 8; i++) {
      data[real_length - i - 1] = ((length * 8) >> (8 * (7 - i))) & 0xFF;
    }
  } else {
    // big endian
    for (int i = 0; i < 8; i++) {
      data[real_length - i - 1] = ((length * 8) >> (8 * i)) & 0xFF;
    }
  }
}
