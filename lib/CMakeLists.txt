add_library(${lib_crypto} SHARED src/crypto.cpp)
target_include_directories(${lib_crypto} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

get_target_property(LIB_INCLUDES ${lib_crypto} INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "Include paths for ${lib_crypto}: ${LIB_INCLUDES}")

set_target_properties(${lib_crypto} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

target_compile_definitions(${lib_crypto}
    PUBLIC SIMPLECRYPTO_EXPORTS
)

add_executable(test0 src/test0.cpp)
add_executable(test1 src/test1.cpp)
add_executable(crack src/crack.cpp)

set_target_properties(test0 test1 crack PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

target_link_libraries(test0 PRIVATE ${lib_crypto})
target_link_libraries(test1 PRIVATE ${lib_crypto})
target_link_libraries(crack PRIVATE ${lib_crypto})

enable_testing()

add_test(NAME test0 COMMAND test0 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME test1 COMMAND test1 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME crack COMMAND crack WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})


if(NOT CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/install" CACHE PATH "Install path prefix" FORCE)
endif()

install(TARGETS ${lib_crypto}
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)

#install(DIRECTORY include DESTINATION include)