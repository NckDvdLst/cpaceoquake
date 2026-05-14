cmake_minimum_required(VERSION 4.2)
project(cpaceoquake C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

file(GLOB MLKEM_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/mlkem/*.c
)

add_library(mlkem STATIC ${MLKEM_SOURCES})

target_include_directories(mlkem PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native
        ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/mlkem
)

file(GLOB CPACE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/cpace/src/*.c
)
add_library(cpace STATIC ${CPACE_SOURCES})
target_include_directories(cpace PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/cpace/src
)
target_link_libraries(cpace PRIVATE ${SODIUM_LIBRARIES})

add_executable(cpaceoquake test/main.c
        src/cpaceoquake.c
        src/oquake.c
        src/oquake_utils.c
        src/cpaceoquake_crypto_utils.c
        )

target_link_libraries(cpaceoquake PRIVATE ${SODIUM_LIBRARIES})
target_link_libraries(cpaceoquake PRIVATE OpenSSL::Crypto)
target_link_libraries(cpaceoquake PRIVATE mlkem)
target_link_libraries(cpaceoquake PRIVATE cpace)

target_include_directories(cpaceoquake
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/mlkem-native/mlkem
        ${CMAKE_CURRENT_SOURCE_DIR}/cpace/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_source_files_properties(
        test/main.c
        src/cpaceoquake.c
        src/oquake.c
        src/oquake_utils.c
        src/cpaceoquake_crypto_utils.c
        PROPERTIES LANGUAGE C
)
