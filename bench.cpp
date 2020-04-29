#include "crypto.h"
#include "util.h"
#include <chrono>
using namespace std;

enum Algorithm { DES, AES128, SM4, RC4, SHA224, SHA256, SHA384, SHA512 };

int main() {
  int input_bytes = 16 * 1024 / 8; // 16Kbit
  int repeat = 1000;
  std::vector<uint8_t> input(input_bytes);
  random_fill(input);
  for (auto algo :
       {Algorithm::DES, Algorithm::AES128, Algorithm::SM4, Algorithm::RC4}) {
    for (bool enc : {true, false}) {
      size_t key_size = 0;
      size_t iv_size = 0;
      const char *algo_name;
      if (algo == Algorithm::DES) {
        key_size = 8;
        iv_size = 8;
        algo_name = "DES";
      } else if (algo == Algorithm::AES128) {
        key_size = 16;
        iv_size = 16;
        algo_name = "AES128";
      } else if (algo == Algorithm::SM4) {
        key_size = 16;
        iv_size = 16;
        algo_name = "SM4";
      } else if (algo == Algorithm::RC4) {
        key_size = 128;
        iv_size = 128; // useless
        algo_name = "RC4";
      }
      std::vector<uint8_t> key(key_size);
      std::vector<uint8_t> iv(iv_size);
      random_fill(key);
      random_fill(iv);
      std::vector<uint8_t> output;
      auto start = chrono::high_resolution_clock::now();
      for (int i = 0; i < repeat; i++) {
        if (algo == Algorithm::DES) {
          des_cbc(enc, input, key, iv, output);
        } else if (algo == Algorithm::AES128) {
          aes128_cbc(enc, input, key, iv, output);
        } else if (algo == Algorithm::SM4) {
          sm4_cbc(enc, input, key, iv, output);
        } else if (algo == Algorithm::RC4) {
          rc4(input, key, output);
        }
      }
      auto end = chrono::high_resolution_clock::now();
      auto time_us =
          chrono::duration_cast<chrono::microseconds>(end - start).count();
      double throughput = (double)input_bytes * 1000000.0 * repeat / time_us;

      printf("Algo %s %s Throughput: %.2lf Mbps or %.2f MiB/s\n", algo_name,
             enc ? "Encrypt" : "Decrypt", throughput * 8.0 / 1024.0 / 1024.0,
             throughput / 1024.0 / 1024.0);
    }
  }

  for (auto algo : {Algorithm::SHA224, Algorithm::SHA256, Algorithm::SHA384, Algorithm::SHA512}) {
    const char *algo_name;
    if (algo == Algorithm::SHA224) {
      algo_name = "SHA224";
    } else if (algo == Algorithm::SHA256) {
      algo_name = "SHA256";
    } else if (algo == Algorithm::SHA384) {
      algo_name = "SHA384";
    } else if (algo == Algorithm::SHA512) {
      algo_name = "SHA512";
    }
    auto start = chrono::high_resolution_clock::now();
    std::vector<uint8_t> output;
    for (int i = 0; i < repeat; i++) {
      if (algo == Algorithm::SHA224) {
        sha224(input, output);
      } else if (algo == Algorithm::SHA256) {
        sha256(input, output);
      } else if (algo == Algorithm::SHA384) {
        sha384(input, output);
      } else if (algo == Algorithm::SHA512) {
        sha512(input, output);
      }
    }
    auto end = chrono::high_resolution_clock::now();
    auto time_us =
        chrono::duration_cast<chrono::microseconds>(end - start).count();
    double throughput = (double)input_bytes * 1000000.0 * repeat / time_us;

    printf("Algo %s Throughput: %.2lf Mbps or %.2f MiB/s\n", algo_name,
           throughput * 8.0 / 1024.0 / 1024.0, throughput / 1024.0 / 1024.0);
  }
  return 0;
}