#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __BASE58_INCLUDED)
  set(__BASE58_INCLUDED TRUE)

  ExternalProject_Add(
    base58_download
    PREFIX ${PROJECT_BINARY_DIR}/base58
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME b1dd03fa8d1be4be076bb6152325c6b5cf64f678.tar.gz
    URL https://github.com/bitcoin/libbase58/archive/b1dd03fa8d1be4be076bb6152325c6b5cf64f678.tar.gz
    URL_HASH SHA256=73b4c9bbb2002f781df6b92e40a5ed2b38ef74dfbf90ce83dc6e18af52e7a4b8
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_COMMAND ""
    # for debug
    # LOG_DOWNLOAD 1
  )

  set(base58_cmake_dir ${PROJECT_BINARY_DIR}/base58/src/ext_base58)
  set(base58_src_dir ../base58_download)
  set(base58_install_include ${CMAKE_INSTALL_PREFIX}/include/)
  set(base58_install_lib ${CMAKE_INSTALL_PREFIX}/lib)

  file(WRITE ${base58_cmake_dir}/CMakeLists.txt
    "cmake_minimum_required(VERSION 3.5)\n"
    "project(Base58 C)\n"
    "add_library(base58 STATIC ${base58_src_dir}/base58.c)\n"
    "target_include_directories(base58 PUBLIC ${base58_src_dir})\n"
    "install(TARGETS base58 DESTINATION ${base58_install_lib})\n"
    "install(FILES ${base58_src_dir}/libbase58.h DESTINATION ${base58_install_include})\n"
  )

  ExternalProject_Add(
    ext_base58
    PREFIX ${PROJECT_BINARY_DIR}/base58
    DOWNLOAD_COMMAND ""
    BUILD_IN_SOURCE TRUE
    CMAKE_ARGS
      -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
      -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}
      -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
    # for debug
    # LOG_CONFIGURE 1
    # LOG_INSTALL 1
  )
  add_dependencies(ext_base58 base58_download)

endif()
