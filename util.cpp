#include "util.h"

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