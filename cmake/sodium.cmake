#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __SODIUM_INCLUDED)
  set(__SODIUM_INCLUDED TRUE)

  set(sodium_src_dir ${PROJECT_BINARY_DIR}/libsodium/src/sodium)

  ExternalProject_Add(
    sodium
    PREFIX ${PROJECT_BINARY_DIR}/libsodium
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME libsodium-1.0.18-stable.tar.gz
    URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable.tar.gz
    # URL_HASH SHA256=2ef4304dd844e274d78dfcf0201e1ba1a312eaba135bdc8affc56a3d80b58593
    BUILD_IN_SOURCE TRUE
    CONFIGURE_COMMAND ${sodium_src_dir}/configure --prefix=${CMAKE_INSTALL_PREFIX} --disable-shared CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
    # BUILD_COMMAND make
    # INSTALL_COMMAND ""
    # for debug
    # LOG_DOWNLOAD 1
  )

endif()
