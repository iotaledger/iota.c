#[[
Copyright (c) 2019 IOTA Stiftung
https://github.com/iotaledger/iota.c

Refer to the LICENSE file for licensing information
]]

cmake_minimum_required(VERSION 3.15)

project(iota_client DESCRIPTION "IOTA Client Library")

enable_language(C)
enable_testing()

option(CCLIENT_TESTS "Enable CClient library test cases" ON)
option(CCLIENT_EXAMPLES "Enable CClient examples" OFF)

# fetch iota_common
include(FetchContent)
FetchContent_Declare(
  iota_common
  GIT_REPOSITORY http://github.com/oopsmonk/iota_common.git
  GIT_TAG dev_chrysalis)

message(STATUS "Fetching iota_common")
FetchContent_MakeAvailable(iota_common)

# fetch external libs
include(ExternalProject)

include(cmake/cjson.cmake)

find_package(CURL REQUIRED)
set(IOTA_CLIENT_EXTERNAL_HEADERS "${CMAKE_INSTALL_PREFIX}/include" "${CURL_INCLUDE_DIRS}")

set(IOTA_CLIENT_EXT_LIBS iota_common "${CURL_LIBRARIES}")

# message(STATUS "libs: ${IOTA_CLIENT_EXT_LIBS}") message(STATUS "headers: ${IOTA_CLIENT_EXTERNAL_HEADERS}")

# libs in the sandbox
link_directories("${CMAKE_INSTALL_PREFIX}/lib")

add_subdirectory(src)

if(CCLIENT_TESTS)
  add_subdirectory(tests)
endif()
