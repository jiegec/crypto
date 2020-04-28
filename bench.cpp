#include "crypto.h"
#include "util.h"
#include <chrono>
using namespace std;

int main() {
  int input_bytes = 16 * 1024; // 16KB
  std::vector<uint8_t> key(8);
  std::vector<uint8_t> iv(8);
  std::vector<uint8_t> input(input_bytes);
  random_fill(key);
  random_fill(iv);
  random_fill(input);
  std::vector<uint8_t> output;
  int repeat = 1000;
  auto start = chrono::high_resolution_clock::now();
  for (int i = 0; i < repeat; i++) {
    des_cbc(true, input, key, iv, output);
  }
  auto end = chrono::high_resolution_clock::now();
  auto time_ms =
      chrono::duration_cast<chrono::milliseconds>(end - start).count();
  double throughput = (double)input_bytes * 1000.0 * repeat / time_ms;
  printf("Done %d des cbc in %.2fs\n", repeat, time_ms / 1000.0);
  printf("Throughput: %2.f Kbps\n", throughput * 8.0 / 1024.0);
  return 0;
}