#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __UTHASH_INCLUDED)
  set(__UTHASH_INCLUDED TRUE)

  ExternalProject_Add(
    ext_uthash
    PREFIX ${PROJECT_BINARY_DIR}/uthash
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    URL https://github.com/troydhanson/uthash/archive/v2.2.0.tar.gz
    URL_HASH SHA256=51e31e9e349c3466c7cea25077a9bb5bc722eff2a2915410763d3616099a4b34
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
                    <SOURCE_DIR>/src ${CMAKE_INSTALL_PREFIX}/include
  )

endif()
