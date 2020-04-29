#include "crypto.h"
#include <cassert>
#include <vector>

using namespace std;

void aes128_cbc(bool encrypt, const vector<uint8_t> &input,
             const vector<uint8_t> &key, const vector<uint8_t> &iv,
             vector<uint8_t> &output) {}