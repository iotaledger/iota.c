#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

add_library(iota_crypto STATIC)
# the required minimum C standard
set_target_properties(iota_crypto PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_crypto
  PRIVATE "iota_crypto.c"
  PUBLIC "iota_crypto.h")

target_include_directories(iota_crypto PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CMAKE_INSTALL_PREFIX}/include")

target_compile_options(iota_crypto PRIVATE -Wall -Wextra)

if(__ED25519_INCLUDE)
  target_compile_definitions(iota_crypto PUBLIC CRYPTO_USE_ED25519_DONNA)
  target_link_libraries(iota_crypto INTERFACE ed25519_donna)
  add_dependencies(iota_crypto ext_ed25519)
endif()

if(__BLAKE2_INCLUDE)
  target_compile_definitions(iota_crypto PUBLIC CRYPTO_USE_BLAKE2B_REF)
  target_link_libraries(iota_crypto INTERFACE blake2)
  add_dependencies(iota_crypto ext_blake2)
endif()

if(CryptoUse STREQUAL "openssl")
  target_compile_definitions(iota_crypto PUBLIC CRYPTO_USE_OPENSSL)
  target_include_directories(iota_crypto PUBLIC "${OPENSSL_INCLUDE_DIR}")
  target_link_libraries(iota_crypto INTERFACE ${OPENSSL_LIBRARIES})
elseif(CryptoUse STREQUAL "libsodium")
  target_compile_definitions(iota_crypto PUBLIC CRYPTO_USE_SODIUM)
  add_dependencies(iota_crypto sodium)
  target_link_libraries(iota_crypto INTERFACE sodium)
elseif(CryptoUse STREQUAL "mbedtls")
  target_compile_definitions(iota_crypto PUBLIC CRYPTO_USE_MBEDTLS)
  add_dependencies(iota_crypto ext_mbedtls)
  target_link_libraries(iota_crypto INTERFACE mbedcrypto mbedtls mbedx509)
endif()

if(__JEMALLOC_INCLUDED)
  add_dependencies(iota_crypto jemalloc)
  target_link_libraries(iota_crypto PUBLIC jemalloc${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
  target_compile_definitions(iota_crypto PUBLIC USE_JEMALLOC)
  target_link_options(iota_crypto PUBLIC -Wl,--no-as-needed -ldl)
endif()

# install headers
install(TARGETS iota_crypto DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(FILES "${PROJECT_SOURCE_DIR}/src/crypto/iota_crypto.h" DESTINATION "${CMAKE_INSTALL_PREFIX}/include/crypto")
