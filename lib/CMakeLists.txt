set(lib_name ${PROJECT_NAME}${PROJECT_VERSION})

add_library(${lib_name} SHARED src/crypto.cpp)
target_include_directories(${lib_name} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(${lib_name} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

target_compile_definitions(${lib_name}
    PUBLIC SIMPLECRYPTO_EXPORTS
)

add_executable(test0 src/test0.cpp)
add_executable(test1 src/test1.cpp)

set_target_properties(test0 test1 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_link_libraries(test0 PRIVATE ${lib_name})
target_link_libraries(test1 PRIVATE ${lib_name})

add_test(NAME test0 COMMAND test0)
add_test(NAME test1 COMMAND test1)

if(NOT CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/install" CACHE PATH "Install path prefix" FORCE)
endif()

install(TARGETS ${lib_name}
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)

install(DIRECTORY include DESTINATION include)