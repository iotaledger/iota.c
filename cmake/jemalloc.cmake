#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __JEMALLOC_INCLUDED)
  set(__JEMALLOC_INCLUDED TRUE)

  set(jemalloc_src_dir ${PROJECT_BINARY_DIR}/jemalloc/src/jemalloc)

  if(${CMAKE_BUILD_TYPE} MATCHES Debug)
    ExternalProject_Add(
      jemalloc
      PREFIX ${PROJECT_BINARY_DIR}/jemalloc
      DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
      DOWNLOAD_NAME jemalloc-5.2.1.tar.bz2
      URL https://github.com/jemalloc/jemalloc/releases/download/5.2.1/jemalloc-5.2.1.tar.bz2
      URL_HASH SHA256=34330e5ce276099e2e8950d9335db5a875689a4c6a56751ef3b1d8c537f887f6
      BUILD_IN_SOURCE TRUE
      CONFIGURE_COMMAND ${jemalloc_src_dir}/configure --enable-debug --enable-log --prefix=${CMAKE_INSTALL_PREFIX} CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
      BUILD_COMMAND make build_lib install_lib install_include -j10
      # INSTALL_COMMAND ""
      # for debug
      # LOG_DOWNLOAD 1
    )
  else()
    ExternalProject_Add(
      jemalloc
      PREFIX ${PROJECT_BINARY_DIR}/jemalloc
      DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
      DOWNLOAD_NAME jemalloc-5.2.1.tar.bz2
      URL https://github.com/jemalloc/jemalloc/releases/download/5.2.1/jemalloc-5.2.1.tar.bz2
      URL_HASH SHA256=34330e5ce276099e2e8950d9335db5a875689a4c6a56751ef3b1d8c537f887f6
      BUILD_IN_SOURCE TRUE
      CONFIGURE_COMMAND ${jemalloc_src_dir}/configure --prefix=${CMAKE_INSTALL_PREFIX} CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
      BUILD_COMMAND make build_lib install_lib install_include -j10
      # INSTALL_COMMAND ""
      # for debug
      # LOG_DOWNLOAD 1
    )
  endif()

  # add_library(malloc::jemalloc ALIAS jemalloc)

  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
endif()
