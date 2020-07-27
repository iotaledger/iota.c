#[[
Copyright (c) 2019 IOTA Stiftung
https://github.com/iotaledger/iota.c

Refer to the LICENSE file for licensing information
]]

if (NOT __MBEDTLS_INCLUDED)
  set(__MBEDTLS_INCLUDED TRUE)

  ExternalProject_Add(
    mbedtls_download
    PREFIX ${PROJECT_BINARY_DIR}/mbedtls
    SOURCE_DIR ${PROJECT_BINARY_DIR}/mbedtls/src/ext_mbedtls
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME mbedtls_v2.23.0.tar.gz
    URL https://github.com/ARMmbed/mbedtls/archive/mbedtls-2.23.0.tar.gz
    URL_HASH SHA256=5c8998217402aa1fc734f4afaeac38fad2421470fac4b3abc112bd46391054fe
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