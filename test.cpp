#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "crypto.h"
#include "util.h"

TEST_CASE("DES Encrypt", "") {
  // example taken from
  // http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
  std::string iv = "0000000000000000";
  std::string key = "133457799BBCDFF1";
  std::string input = "0123456789ABCDEF";
  std::vector<uint8_t> vec_output;
  SECTION("encrypt with zero iv") {
    std::string output = "85E813540F0AB405";
    des_cbc(true, parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv),
            vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("encrypt with non-zero iv") {
    std::string iv = "000000000000000F";
    std::string output = "AE26A69343ACEF30";
    des_cbc(true, parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv),
            vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("encrypt with non-zero iv with two blocks") {
    std::string iv = "000000000000000F";
    std::string input = "0123456789ABCDEF0123456789ABCDEF";
    std::string output = "AE26A69343ACEF305E7FE8F06ECE74E7";
    des_cbc(true, parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv),
            vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("decrypt with zero iv") {
    std::string input = "85E813540F0AB405";
    std::string output = "0123456789ABCDEF";
    des_cbc(false, parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv),
            vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("decrypt with non-zero iv") {
    std::string iv = "000000000000000F";
    std::string input = "AE26A69343ACEF30";
    std::string output = "0123456789ABCDEF";
    des_cbc(false, parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv),
            vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("decrypt with non-zero iv with two blocks") {
    std::string iv = "000000000000000F";
    std::string input = "AE26A69343ACEF305E7FE8F06ECE74E7";
    std::string output = "0123456789ABCDEF0123456789ABCDEF";
    des_cbc(false, parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv),
            vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}