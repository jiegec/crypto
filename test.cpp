#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "crypto.h"
#include "util.h"

TEST_CASE("DES", "") {
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
  SECTION("encrypt with padding") {
    std::string input = "00";
    std::vector<uint8_t> vec_input = parse_hex_new(input);
    pkcs7_pad(vec_input, 8);
    std::string output = "58D2AC9FFD299DC1";
    des_cbc(true, vec_input, parse_hex_new(key), parse_hex_new(iv), vec_output);
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

TEST_CASE("AES", "") {
  // example taken from
  // https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
  std::string iv = "00000000000000000000000000000000";
  std::string key = "5468617473206D79204B756E67204675";
  std::string input = "54776F204F6E65204E696E652054776F";
  std::vector<uint8_t> vec_output;
  SECTION("encrypt with zero iv") {
    std::string output = "29c3505f571420f6402299b31a02d73a";
    aes128_cbc(true, parse_hex_new(input), parse_hex_new(key),
               parse_hex_new(iv), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("encrypt with padding") {
    std::vector<uint8_t> vec_input = parse_hex_new(input);
    pkcs7_pad(vec_input, 16);
    std::string output =
        "29c3505f571420f6402299b31a02d73a5f5917ec376a3a269efadb6b2d61e4e3";
    aes128_cbc(true, vec_input, parse_hex_new(key), parse_hex_new(iv),
               vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("decrypt with zero iv") {
    std::string input = "29c3505f571420f6402299b31a02d73a";
    std::string output = "54776F204F6E65204E696E652054776F";
    aes128_cbc(false, parse_hex_new(input), parse_hex_new(key),
               parse_hex_new(iv), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SM4", "") {
  // example taken from
  // https://tools.ietf.org/id/draft-crypto-sm4-00.html
  std::string iv = "00000000000000000000000000000000";
  std::string key = "0123456789ABCDEFFEDCBA9876543210";
  std::string input = "0123456789ABCDEFFEDCBA9876543210";
  std::vector<uint8_t> vec_output;
  SECTION("encrypt with zero iv") {
    std::string output = "681EDF34D206965E86B3E94F536E4246";
    sm4_cbc(true, parse_hex_new(input), parse_hex_new(key), parse_hex_new(iv),
            vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("RC4", "") {
  // example taken from
  // https://en.wikipedia.org/wiki/RC4
  std::vector<uint8_t> vec_output;
  SECTION("encrypt Plaintext with Key") {
    std::string key = "4B6579";
    std::string input = "506C61696E74657874";
    std::string output = "BBF316E8D940AF0AD3";
    rc4(parse_hex_new(input), parse_hex_new(key), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("encrypt pedia with Wiki") {
    std::string key = "57696B69";
    std::string input = "7065646961";
    std::string output = "1021BF0420";
    rc4(parse_hex_new(input), parse_hex_new(key), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("BM", "") {
  // example taken from slides
  std::vector<uint8_t> vec_output;
  SECTION("reverse 00101010010001") {
    std::string input = "00101010010001";
    // 1 + x + x^2 + x^4 + x^5
    std::string output = "111011";
    bm(std::vector<uint8_t>(input.begin(), input.end()), vec_output);
    REQUIRE(std::string(vec_output.begin(), vec_output.end()) == output);
  }
}

TEST_CASE("SHA256", "") {
  std::vector<uint8_t> vec_output;
  SECTION("sha256 of test") {
    std::string input = "74657374";
    std::string output =
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    sha256(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}