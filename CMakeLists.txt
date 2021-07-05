#[[
Copyright (c) 2019 IOTA Stiftung
https://github.com/iotaledger/iota.c

Refer to the LICENSE file for licensing information
]]

cmake_minimum_required(VERSION 3.15)

project(iota_client DESCRIPTION "IOTA Client Library")

enable_language(C)
enable_testing()

option(IOTA_TESTS "Enable IOTA Client library test cases" ON)
option(IOTA_ASAN_ENABLED "Enable Address sanitizer" OFF)
option(ENABLED_JEMALLOC "Enable jemalloc memory allocator" OFF)
option(IOTA_EXAMPLES "Build example application" ON)
# ~~~
# Notice #####
# USE_REF_CRYPTO only support GCC compiler and Openssl is required.
# ed25519-donna has a compiling issue with clang 11
# ed25519-donna-64bit-x86.h:14:3: error: inline assembly requires more registers than available
#                  "movq %0, %%rax                  ;\n"
#                  ^
# ~~~
option(USE_REF_CRYPTO "Use ed25519_donna, blake2, openssl as crypto implementation" OFF)

# fetch external libs
include(ExternalProject)

include(cmake/unity.cmake)
include(cmake/cjson.cmake)
include(cmake/uthash.cmake)
if(USE_REF_CRYPTO)
  message("Crypto uses OpenSSL and external libs")
  find_package(OpenSSL REQUIRED)
  include(cmake/blake2.cmake)
  include(cmake/ed25519_donna.cmake)
else()
  message("Crypto uses libsodium")
  include(cmake/sodium.cmake)
endif()
# include(cmake/base58.cmake)

if(ENABLED_JEMALLOC)
  include(cmake/jemalloc.cmake)
endif()

if(IOTA_ASAN_ENABLED)
  if(UNIX AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR NOT CMAKE_BUILD_TYPE))
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      # ~~~
      # uthash causes runtime error if enable the unsigned-integer-overflow sanitizer in clang.
      # see: https://github.com/pmodels/mpich/issues/3322
      # add_compile_options("-fsanitize=address,undefined,unsigned-integer-overflow"
      #   "-fno-omit-frame-pointer"
      #   "-fsanitize-address-use-after-scope"
      #   "-fno-sanitize-recover=undefined,unsigned-integer-overflow")
      # ~~~
      add_compile_options(
        "-fsanitize=address,undefined"
        "-fno-omit-frame-pointer"
        "-fno-sanitize=unsigned-integer-overflow"
        "-fsanitize-address-use-after-scope"
        "-fno-sanitize-recover=undefined")
      add_link_options("-fsanitize=address,undefined")
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
      add_compile_options("-fsanitize=address,undefined" "-fno-omit-frame-pointer" "-fsanitize-address-use-after-scope"
                          "-fno-sanitize-recover=undefined")
      add_link_options("-fsanitize=address,undefined")
    endif()
  else()
    message(WARNING "Sanitizer is not supported on Windows or Release build")
  endif()
endif()

find_package(CURL REQUIRED)

# links libraries in the sandbox
link_directories("${CMAKE_INSTALL_PREFIX}/lib")

add_subdirectory(src)

if(IOTA_TESTS)
  add_subdirectory(tests)
endif()

if(IOTA_EXAMPLES)
  add_subdirectory(examples)
endif()
