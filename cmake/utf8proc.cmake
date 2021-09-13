#[[
// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __UTF8PROC_INCLUDED)
  set(__UTF8PROC_INCLUDED TRUE)

  ExternalProject_Add(
    ext_utf8proc
    PREFIX ${PROJECT_BINARY_DIR}/utf8proc
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME utf8proc_v2.6.1.tar.gz
    URL https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.6.1.tar.gz
    URL_HASH SHA256=4c06a9dc4017e8a2438ef80ee371d45868bda2237a98b26554de7a95406b283b
    CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}
    -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    # -DCMAKE_TOOLCHAIN_FILE:STRING=${CMAKE_TOOLCHAIN_FILE}
    # for debug
    # LOG_DOWNLOAD 1
    # LOG_CONFIGURE 1
    # LOG_INSTALL 1
  )
endif()