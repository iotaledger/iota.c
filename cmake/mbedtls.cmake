#[[
// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __MBEDTLS_INCLUDED)
  set(__MBEDTLS_INCLUDED TRUE)

  set(MBEDTLS_VERSION "v2.28.0")

  ExternalProject_Add(
    mbedtls_download
    PREFIX ${PROJECT_BINARY_DIR}/mbedtls
    SOURCE_DIR ${PROJECT_BINARY_DIR}/mbedtls/src/ext_mbedtls
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME mbedtls_${MBEDTLS_VERSION}.tar.gz
    URL https://github.com/ARMmbed/mbedtls/archive/refs/tags/${MBEDTLS_VERSION}.tar.gz
    URL_HASH SHA256=6519579b836ed78cc549375c7c18b111df5717e86ca0eeff4cb64b2674f424cc
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_COMMAND ""
    # for debug
    # LOG_DOWNLOAD 1
  )

  ExternalProject_Add(
    ext_mbedtls
    PREFIX ${PROJECT_BINARY_DIR}/mbedtls
    DOWNLOAD_COMMAND ""
    CMAKE_ARGS
      -DENABLE_TESTING=Off 
      -DENABLE_PROGRAMS=Off
      -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}
    #  -DCMAKE_TOOLCHAIN_FILE:STRING=${CMAKE_TOOLCHAIN_FILE}
    # for debug
    # LOG_CONFIGURE 1
    # LOG_INSTALL 1
  )

  add_dependencies(ext_mbedtls mbedtls_download)

endif()
