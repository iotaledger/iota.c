#[[
// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __ED25519_INCLUDE)
  set(__ED25519_INCLUDE TRUE)

  # find_package(OpenSSL REQUIRED)

  ExternalProject_Add(
    ed25519_download
    PREFIX ${PROJECT_BINARY_DIR}/ed25519
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    # DOWNLOAD_NAME 8757bd4cd209cb032853ece0ce413f122eef212c.tar.gz
    URL https://github.com/floodyberry/ed25519-donna/archive/8757bd4cd209cb032853ece0ce413f122eef212c.tar.gz
    URL_HASH SHA256=affbf8078b963f449fdafbc49a1e98389c6abf65fc6d49b051e7cbcf60764d1e
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_COMMAND ""
    # for debug
    # LOG_DOWNLOAD 1
  )

  set(ed25519_cmake_dir ${PROJECT_BINARY_DIR}/ed25519/src/ext_ed25519)
  set(ed25519_src_dir ../ed25519_download)
  set(ed25519_install_include ${CMAKE_INSTALL_PREFIX}/include/)
  set(ed25519_install_lib ${CMAKE_INSTALL_PREFIX}/lib)

  file(WRITE ${ed25519_cmake_dir}/CMakeLists.txt
    "cmake_minimum_required(VERSION 3.5)\n"
    "project(ed25519 C)\n"
    "# find_package(OpenSSL REQUIRED)\n"
    "message(\"OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}\")\n"
    "message(\"OpenSSL libraries: ${OPENSSL_LIBRARIES}\")\n"
    "add_library(ed25519_donna STATIC)\n"
    "target_sources(\n"
    "ed25519_donna\n"
    "PRIVATE \"${ed25519_src_dir}/curve25519-donna-32bit.h\"\n"
    "  \"${ed25519_src_dir}/curve25519-donna-64bit.h\"\n"
    "  \"${ed25519_src_dir}/curve25519-donna-helpers.h\"\n"
    "  \"${ed25519_src_dir}/curve25519-donna-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519.c\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-32bit-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-32bit-tables.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-tables.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-x86-32bit.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-x86.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-basepoint-table.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-batchverify.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-impl-base.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-impl-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-portable.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-portable-identify.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-hash-custom.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-hash.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-randombytes-custom.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-randombytes.h\"\n"
    "  \"${ed25519_src_dir}/modm-donna-32bit.h\"\n"
    "  \"${ed25519_src_dir}/modm-donna-64bit.h\"\n"
    "PUBLIC \"${ed25519_src_dir}/ed25519.h\")\n"
    "target_link_libraries(ed25519_donna PUBLIC ${OPENSSL_LIBRARIES})\n"
    "target_include_directories(ed25519_donna PUBLIC ${ed25519_src_dir} ${OPENSSL_INCLUDE_DIR})\n"
    "install(TARGETS ed25519_donna DESTINATION ${ed25519_install_lib})\n"
    "install(FILES ${ed25519_src_dir}/ed25519.h DESTINATION ${ed25519_install_include})\n"
  )

  ExternalProject_Add(
    ext_ed25519
    PREFIX ${PROJECT_BINARY_DIR}/ed25519
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
  add_dependencies(ext_ed25519 ed25519_download)

endif()
