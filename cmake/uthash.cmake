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
    URL https://github.com/troydhanson/uthash/archive/v2.3.0.tar.gz
    URL_HASH SHA256=e10382ab75518bad8319eb922ad04f907cb20cccb451a3aa980c9d005e661acc
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
                    <SOURCE_DIR>/src ${CMAKE_INSTALL_PREFIX}/include
  )

endif()
