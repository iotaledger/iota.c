#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

add_library(iota_wallet STATIC)

# the required minimum C standard
set_target_properties(iota_wallet PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

add_dependencies(iota_wallet iota_client)

target_sources(
  iota_wallet
  PRIVATE "wallet.c"
  PUBLIC "wallet.h")

target_include_directories(
  iota_wallet PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CURL_INCLUDE_DIRS}"
                     "${CMAKE_INSTALL_PREFIX}/include/cjson" # for esp32 compatibility
)

add_dependencies(iota_wallet iota_client)

target_link_libraries(iota_wallet PUBLIC iota_client)

# install client lib and headers
install(TARGETS iota_wallet DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/wallet/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wallet"
  FILES_MATCHING
  PATTERN "*.h")
