#[[
Copyright (c) 2019 IOTA Stiftung
https://github.com/iotaledger/iota.c

Refer to the LICENSE file for licensing information
]]

if (NOT __IOTA_CORE_INCLUDED)
  set(__IOTA_CORE_INCLUDED TRUE)

  ExternalProject_Add(
    ext_iota_common
    PREFIX ${PROJECT_BINARY_DIR}/iota_common
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME iota_common-master.tar.gz
    URL https://github.com/iotaledger/iota_common/archive/master.tar.gz
    URL_HASH SHA256=730c33e7289470fcd8c31b2355e1378d823fe3068d8b7424bc693c71cc7898a0
    CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}
    # -DCMAKE_TOOLCHAIN_FILE:STRING=${CMAKE_TOOLCHAIN_FILE}
    # for debug
    # LOG_DOWNLOAD 1
    # LOG_CONFIGURE 1
    # LOG_INSTALL 1
  )
endif()