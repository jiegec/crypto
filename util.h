#ifndef __UTIL_H__
#define __UTIL_H__

#include <vector>
#include <string>

void parse_hex(const std::string &input, std::vector<uint8_t> &output);
std::vector<uint8_t> parse_hex_new(const std::string &input);
void random_fill(std::vector<uint8_t> &data);

#endif