add_executable(cli src/cli.cpp)
target_link_libraries(cli PRIVATE ${lib_crypto})

set(link_OMP false)

if(link_OMP)
    find_package(OpenMP)

    if(OpenMP_FOUND)
        message(STATUS "OpenMP found.")
        target_compile_options(cli PRIVATE ${OpenMP_CXX_FLAGS})
        target_compile_options(cli PRIVATE -DOMP)
        target_link_libraries(cli PRIVATE ${OpenMP_CXX_LIBRARIES})
    else()
        message(STATUS "OpenMP not found.")
    endif()
endif()

set_target_properties(cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

enable_testing()
add_test(NAME cli_test0 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cli --encrypt --key-file test1.sckey --data-file test.txt -v)
add_test(NAME cli_test1 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND cli --encrypt --key ab12cd34 --data cumhuriyet1923 -v)
