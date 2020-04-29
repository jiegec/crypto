#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <vector>

// block cipher
void des_cbc(bool encrypt, const std::vector<uint8_t> &input,
             const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
             std::vector<uint8_t> &output);
void aes128_cbc(bool encrypt, const std::vector<uint8_t> &input,
                const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
                std::vector<uint8_t> &output);
void sm4_cbc(bool encrypt, const std::vector<uint8_t> &input,
             const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv,
             std::vector<uint8_t> &output);

// stream cipher
void rc4(const std::vector<uint8_t> &input, const std::vector<uint8_t> &key,
         std::vector<uint8_t> &output);

// reverse lfsr
void bm(const std::vector<uint8_t> &input, std::vector<uint8_t> &output);

#endif