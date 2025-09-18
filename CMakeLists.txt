cmake_minimum_required(VERSION 3.10.0)
project(simple-cryptography VERSION 0.1.0 LANGUAGES C CXX)

add_library(simple-cryptography SHARED src/crypto.cpp)
target_include_directories(simple-cryptography PUBLIC "${PROJECT_SOURCE_DIR}/include")

#target_compile_definitions(simple-cryptography PRIVATE SIMPLECRYPTO_EXPORTS)

set_target_properties(simple-cryptography PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

add_executable(test0 src/test0.cpp)
add_executable(test1 src/test1.cpp)

set_target_properties(test0 test1 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_link_libraries(test0 PRIVATE simple-cryptography)
target_link_libraries(test1 PRIVATE simple-cryptography)

add_test(NAME test0 COMMAND test0)
add_test(NAME test1 COMMAND test1)

include(CTest)
enable_testing()
