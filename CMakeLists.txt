cmake_minimum_required(VERSION 3.10.0)
project(simple_cryptography VERSION 0.1.0 LANGUAGES C CXX)

set(lib_crypto ${PROJECT_NAME}${PROJECT_VERSION})

add_subdirectory(lib)
add_subdirectory(cli)

include(CTest)
enable_testing()