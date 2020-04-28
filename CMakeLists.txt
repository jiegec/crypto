cmake_minimum_required(VERSION 3.10)
project(crypto)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-fsanitize=address ${CMAKE_CXX_FLAGS}")

add_executable(crypto main.cpp des.cpp)