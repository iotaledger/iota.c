#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __UNITY_INCLUDED)
  set(__UNITY_INCLUDED TRUE)

  ExternalProject_Add(
    ext_unity
    PREFIX ${PROJECT_BINARY_DIR}/unity
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME unity_v2.5.2.tar.gz
    URL https://github.com/ThrowTheSwitch/Unity/archive/v2.5.2.tar.gz
    URL_HASH SHA256=3786de6c8f389be3894feae4f7d8680a02e70ed4dbcce36109c8f8646da2671a
    BUILD_IN_SOURCE TRUE
    CMAKE_ARGS
      -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
      -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}
      -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
    # for debug
    # LOG_CONFIGURE 1
    # LOG_INSTALL 1
  )

endif()
