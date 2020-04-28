#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <vector>

void des_cbc(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key,
             const std::vector<uint8_t> &iv, std::vector<uint8_t> &output);

#endif