#ifndef __UTIL_H__
#define __UTIL_H__

#include <string>
#include <vector>

void parse_hex(const std::string &input, std::vector<uint8_t> &output);
std::vector<uint8_t> parse_hex_new(const std::string &input);
void random_fill(std::vector<uint8_t> &data);
void pkcs7_pad(std::vector<uint8_t> &data, size_t block_size);
void pkcs7_unpad(std::vector<uint8_t> &data, size_t block_size);
std::vector<uint32_t> unpack_uint32_le(const std::vector<uint8_t> &data);
uint64_t get_time_us();
void hash_pad(std::vector<uint8_t> &data, bool little_endian,
              int block_size = 64);

#endif