cmake_minimum_required(VERSION 3.10.0)
project(simple-cryptography VERSION 0.1.0 LANGUAGES C CXX)

add_subdirectory(lib)

include(CTest)
enable_testing()