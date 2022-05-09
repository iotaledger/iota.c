#[[
// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __BLAKE2_INCLUDE)
  set(__BLAKE2_INCLUDE TRUE)

  ExternalProject_Add(
    blake2_download
    PREFIX ${PROJECT_BINARY_DIR}/blake2
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    DOWNLOAD_NAME 54f4faa4c16ea34bcd59d16e8da46a64b259fc07.tar.gz
    URL https://github.com/BLAKE2/BLAKE2/archive/54f4faa4c16ea34bcd59d16e8da46a64b259fc07.tar.gz
    URL_HASH SHA256=710753a61f3f67eff11bc1a4e3374651a266493e6c1691c70197e72c3c6379d9
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_COMMAND ""
    # for debug
    # LOG_DOWNLOAD 1
  )

  set(blake2_cmake_dir ${PROJECT_BINARY_DIR}/blake2/src/ext_blake2)
  set(blake2_src_dir ../blake2_download)
  set(blake2_install_include ${CMAKE_INSTALL_PREFIX}/include/)
  set(blake2_install_lib ${CMAKE_INSTALL_PREFIX}/lib)

  file(WRITE ${blake2_cmake_dir}/CMakeLists.txt
    "cmake_minimum_required(VERSION 3.15)\n"
    "project(blake2 C)\n"
    "add_library(blake2 STATIC)\n"
    "target_sources(\n"
    "blake2\n"
    "PRIVATE \"${blake2_src_dir}/ref/blake2-impl.h\"\n"
    "  \"${blake2_src_dir}/ref/blake2b-ref.c\"\n"
    "  \"${blake2_src_dir}/ref/blake2bp-ref.c\"\n"
    "  \"${blake2_src_dir}/ref/blake2s-ref.c\"\n"
    "  \"${blake2_src_dir}/ref/blake2sp-ref.c\"\n"
    "  \"${blake2_src_dir}/ref/blake2xb-ref.c\"\n"
    "  \"${blake2_src_dir}/ref/blake2xs-ref.c\"\n"
    "PUBLIC \"${blake2_src_dir}/ref/blake2.h\")\n"
    "target_include_directories(blake2 PUBLIC ${base58_src_dir})\n"
    "install(TARGETS blake2 DESTINATION ${blake2_install_lib})\n"
    "install(FILES ${blake2_src_dir}/ref/blake2.h DESTINATION ${blake2_install_include})\n"
  )

  ExternalProject_Add(
    ext_blake2
    PREFIX ${PROJECT_BINARY_DIR}/blake2
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
  add_dependencies(ext_blake2 blake2_download)

endif()
