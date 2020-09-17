#[[
Copyright (c) 2020 IOTA Stiftung
https://github.com/iotaledger/iota_common

Refer to the LICENSE file for licensing information
]]

if (NOT __UTHASH_INCLUDED)
  set(__UTHASH_INCLUDED TRUE)

  ExternalProject_Add(
    ext_uthash
    PREFIX ${PROJECT_BINARY_DIR}/uthash
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    URL https://github.com/troydhanson/uthash/archive/8e67ced1d1c5bd8141c542a22630e6de78aa6b90.tar.gz
    URL_HASH SHA256=192792686335eb9c55a917259e3bd553ea56a15cf3374a9d093bbf31f810dab4
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
                    <SOURCE_DIR>/src ${CMAKE_INSTALL_PREFIX}/include
  )

endif()
