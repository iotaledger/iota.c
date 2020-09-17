#[[
Copyright (c) 2019 IOTA Stiftung
https://github.com/iotaledger/iota.c

Refer to the LICENSE file for licensing information
]]

cmake_minimum_required(VERSION 3.15)

project(iota_client DESCRIPTION "IOTA Client Library")

enable_language(C)
enable_testing()

option(IOTA_TESTS "Enable IOTA Client library test cases" ON)
# option(CCLIENT_EXAMPLES "Enable Client examples" OFF)
option(IOTA_ASAN_ENABLED "Enable Address sanitizer" OFF)

# fetch external libs
include(ExternalProject)

include(cmake/unity.cmake)
include(cmake/cjson.cmake)
include(cmake/uthash.cmake)
include(cmake/sodium.cmake)
include(cmake/base58.cmake)

if(IOTA_ASAN_ENABLED)
  if(UNIX AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR NOT CMAKE_BUILD_TYPE))
    include(CheckCCompilerFlag)
    set(CMAKE_REQUIRED_LIBRARIES "asan")
    if(CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES "GNU")
      check_c_compiler_flag("-fsanitize=address" HAS_ASAN)
      if(HAS_ASAN)
        add_compile_options("-fsanitize=address" "-fno-omit-frame-pointer")
        set(HAS_ASAN_ENABLED
            ON
            CACHE BOOL "Asan has enabled on target" FORCE)
      else()
        message(WARNING "ASan is not supported")
      endif()

    endif()
  else()
    message(WARNING "ASan is not supported on Windows or Release build")
  endif()
endif()

find_package(CURL REQUIRED)

# links libraries in the sandbox
link_directories("${CMAKE_INSTALL_PREFIX}/lib")

add_subdirectory(src)

if(IOTA_TESTS)
  add_subdirectory(tests)
endif()
