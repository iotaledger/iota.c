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
option(IOTA_EXAMPLES "Build example application" OFF)
option(IOTA_WALLET_ENABLE "Enable simple wallet API" ON)
option(MQTT_CLIENT_ENABLE "Enable MQTT Event APIs" OFF)
# Enable for reducing the application binary size
option(BIP39_ENGLISH_ONLY "Support English mnemonic only" OFF)
option(WITH_IOTA_CLIENT "Build library with client module" ON)
option(WITH_IOTA_CORE "Build library with core module" OFF)

set(MainCryptoLibs "openssl" "libsodium" "mbedtls")
set(CryptoUse
    "openssl"
    CACHE STRING "Crypto lib options")
set_property(CACHE CryptoUse PROPERTY STRINGS ${MainCryptoLibs})

if(NOT CryptoUse IN_LIST MainCryptoLibs)
  message(FATAL_ERROR "CryptoUse must be one of ${MainCryptoLibs}")
endif()

if(IOTA_WALLET_ENABLE OR MQTT_CLIENT_ENABLE)
  set(WITH_IOTA_CLIENT ON)
  set(WITH_IOTA_CORE ON)
elseif(WITH_IOTA_CLIENT)
  message("Build with Client/Core/Crypto module")
  set(WITH_IOTA_CORE ON)
elseif(WITH_IOTA_CORE)
  message("Build with Core/Crypto module")
else()
  message("Build with Crypto module only")
endif()

# fetch external libs
include(ExternalProject)

if(IOTA_TESTS)
  include(cmake/unity.cmake)
endif()

if(WITH_IOTA_CLIENT)
  include(cmake/cjson.cmake)
endif()

if(WITH_IOTA_CORE)
  include(cmake/uthash.cmake)
endif()

# cryptography libs comparison https://en.wikipedia.org/wiki/Comparison_of_cryptography_libraries
if(CryptoUse STREQUAL "openssl")
  message("Crypto uses OpenSSL")
  find_package(OpenSSL REQUIRED)
  include(cmake/blake2.cmake)
  include(cmake/ed25519_donna.cmake)
elseif(CryptoUse STREQUAL "libsodium")
  message("Crypto uses libsodium")
  include(cmake/sodium.cmake)
elseif(CryptoUse STREQUAL "mbedtls")
  include(cmake/mbedtls.cmake)
  include(cmake/blake2.cmake)
  include(cmake/ed25519_donna.cmake)
  message("Crypto uses mbedtls ${MBEDTLS_VERSION}")
else()
  message(FATAL_ERROR "Crypto framework is not defined")
endif()

if(IOTA_WALLET_ENABLE)
  message("Enable Wallet API")
  include(cmake/utf8proc.cmake)
endif()

if(MQTT_CLIENT_ENABLE)
  message("Enable MQTT Client")
  include(cmake/mosquitto.cmake)
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
endif()

if(ENABLED_JEMALLOC)
  include(cmake/jemalloc.cmake)
endif()

if(IOTA_ASAN_ENABLED)
  if(UNIX AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR NOT CMAKE_BUILD_TYPE))
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      add_compile_options("-fsanitize=address,undefined,unsigned-integer-overflow" "-fsanitize-address-use-after-scope"
                          "-fno-omit-frame-pointer" "-fno-sanitize-recover=undefined,unsigned-integer-overflow")
      add_link_options("-fsanitize=address,undefined,unsigned-integer-overflow")
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
      add_compile_options("-fsanitize=address,undefined" "-fno-omit-frame-pointer" "-fsanitize-address-use-after-scope"
                          "-fno-sanitize-recover=undefined")
      add_link_options("-fsanitize=address,undefined")
    endif()
  else()
    message(WARNING "Sanitizer is not supported on Windows or Release build")
  endif()
endif()

if(WITH_IOTA_CLIENT)
  find_package(CURL REQUIRED)
endif()

# links libraries in the sandbox
link_directories("${CMAKE_INSTALL_PREFIX}/lib")

add_subdirectory(src)

if(IOTA_TESTS)
  add_subdirectory(tests)
endif()

if(IOTA_EXAMPLES AND WITH_IOTA_CLIENT)
  add_subdirectory(examples)
endif()
