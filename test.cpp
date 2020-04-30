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
  SECTION("sha256 of empty") {
    std::string input = "";
    std::string output =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    sha256(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SHA224", "") {
  std::vector<uint8_t> vec_output;
  SECTION("sha256 of test") {
    std::string input = "74657374";
    std::string output =
        "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809";
    sha224(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sha224 of empty") {
    std::string input = "";
    std::string output =
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
    sha224(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SHA384", "") {
  std::vector<uint8_t> vec_output;
  SECTION("sha384 of test") {
    std::string input = "74657374";
    std::string output = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782"
                         "249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
    sha384(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sha384 of empty") {
    std::string input = "";
    std::string output = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc"
                         "7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    sha384(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SHA512", "") {
  std::vector<uint8_t> vec_output;
  SECTION("sha512 of test") {
    std::string input = "74657374";
    std::string output =
        "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185"
        "f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
    sha512(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sha512 of empty") {
    std::string input = "";
    std::string output =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d1"
        "3c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    sha512(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SM3", "") {
  // examples taken from https://tools.ietf.org/html/draft-oscca-cfrg-sm3-02
  std::vector<uint8_t> vec_output;
  SECTION("sm3 of abc") {
    std::string input = "616263";
    std::string output = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c487"
                         "5cf2f7a2297da02b8f4ba8e0";
    sm3(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sm3 of 512bit input") {
    std::string input =
        "6162636461626364616263646162636461626364616263646162636461626364616263"
        "6461626364616263646162636461626364616263646162636461626364";
    std::string output = "debe9ff92275b8a138604889c18e5a4d6fdb70e5"
                         "387e5765293dcba39c0c5732";
    sm3(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SHA3_224", "") {
  std::vector<uint8_t> vec_output;
  SECTION("sha3_224 of empty string") {
    std::string input = "";
    std::string output =
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    sha3_224(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sha3_224 of test") {
    std::string input = "74657374";
    std::string output =
        "3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b";
    sha3_224(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SHA3_256", "") {
  // examples taken from
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf
  std::vector<uint8_t> vec_output;
  SECTION("sha3_256 of empty string") {
    std::string input = "";
    std::string output =
        "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A";
    sha3_256(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sha3_256 of test") {
    std::string input = "74657374";
    std::string output =
        "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
    sha3_256(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SHA3_384", "") {
  std::vector<uint8_t> vec_output;
  SECTION("sha3_384 of empty string") {
    std::string input = "";
    std::string output = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e7"
                         "1bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    sha3_384(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sha3_384 of test") {
    std::string input = "74657374";
    std::string output = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178"
                         "d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
    sha3_384(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}

TEST_CASE("SHA3_512", "") {
  std::vector<uint8_t> vec_output;
  SECTION("sha3_512 of empty string") {
    std::string input = "";
    std::string output =
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b212"
        "3af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    sha3_512(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
  SECTION("sha3_512 of test") {
    std::string input = "74657374";
    std::string output =
        "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a67828816"
        "6e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
    sha3_512(parse_hex_new(input), vec_output);
    REQUIRE(vec_output == parse_hex_new(output));
  }
}