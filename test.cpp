#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "crypto.h"
#include "util.h"

TEST_CASE("DES Encrypt", "") {
  std::string iv = "0000000000000000";
  std::string key = "133457799BBCDFF1";
  std::string input = "0123456789ABCDEF";
  std::string output = "85E813540F0AB405";
  std::vector<uint8_t> vec_output;
  des_cbc(parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv), vec_output);
  REQUIRE(vec_output == parse_hex_new(output));
}