cmake_minimum_required(VERSION 3.10)
project(crypto)

set(BLT_CXX_STD "c++11" CACHE STRING "")
set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address ${CMAKE_CXX_FLAGS_DEBUG}")

include(blt/SetupBLT.cmake)

blt_add_library(NAME crypto-lib
                HEADERS crypto.h
                SOURCES des.cpp util.cpp aes128.cpp sm4.cpp rc4.cpp bm.cpp sha2.cpp sm3.cpp sha3.cpp md4.cpp)
blt_add_executable(NAME crypto
                   SOURCES main.cpp
		   DEPENDS_ON crypto-lib)
blt_add_executable(NAME crypto-bench
                   SOURCES bench.cpp
		   DEPENDS_ON crypto-lib)
blt_add_executable(NAME crypto-test
                   SOURCES test.cpp
                   DEPENDS_ON crypto-lib gtest)
blt_add_test(NAME crypto-test
             COMMAND crypto-test)