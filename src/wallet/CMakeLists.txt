#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

add_library(iota_wallet STATIC)

# the required minimum C standard
set_target_properties(iota_wallet PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_wallet
  PRIVATE "wallet.c"
          "output_basic.c"
          "output_alias.c"
          "bip39.c"
  PUBLIC "wallet.h"
         "output_basic.h"
         "output_alias.h")

target_include_directories(
  iota_wallet PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CURL_INCLUDE_DIRS}"
                     "${CMAKE_INSTALL_PREFIX}/include/cjson" # for esp32 compatibility
)

add_dependencies(iota_wallet iota_client ext_utf8proc)

target_compile_options(iota_wallet PRIVATE -Wall -Wextra)

if(BIP39_ENGLISH_ONLY)
  target_compile_definitions(iota_wallet PUBLIC BIP39_ENGLISH_ONLY)
endif()

target_link_libraries(iota_wallet PUBLIC iota_client)
target_link_libraries(iota_wallet PRIVATE utf8proc)

# install client lib and headers
install(TARGETS iota_wallet DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/wallet/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wallet"
  FILES_MATCHING
  PATTERN "*.h")
