#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

add_library(iota_core STATIC)
# the required minimum C standard
set_target_properties(iota_core PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_core
  PRIVATE "address.c"
          "utils/iota_str.c"
          "utils/byte_buffer.c"
          "utils/slip10.c"
          "utils/bech32.c"
          "utils/uint256.c"
          "utils/macros.h"
          "models/inputs/utxo_input.c"
          "models/outputs/byte_cost_config.c"
          "models/outputs/feat_blocks.c"
          "models/outputs/output_alias.c"
          "models/outputs/output_basic.c"
          "models/outputs/output_foundry.c"
          "models/outputs/output_nft.c"
          "models/outputs/native_tokens.c"
          "models/outputs/outputs.c"
          "models/outputs/storage_deposit.c"
          "models/outputs/unlock_conditions.c"
          "models/payloads/transaction.c"
          "models/payloads/tagged_data.c"
          "models/payloads/milestone.c"
          "models/message.c"
          #"models/signing.c"
          "models/unlock_block.c"
  PUBLIC "address.h"
         "utils/iota_str.h"
         "utils/byte_buffer.h"
         "utils/slip10.h"
         "utils/bech32.h"
         "utils/uint256.h"
         "utils/macros.h"
         "models/inputs/utxo_input.h"
         "models/outputs/byte_cost_config.h"
         "models/outputs/feat_blocks.h"
         "models/outputs/output_alias.h"
         "models/outputs/output_basic.h"
         "models/outputs/output_foundry.h"
         "models/outputs/output_nft.h"
         "models/outputs/native_tokens.h"
         "models/outputs/outputs.h"
         "models/outputs/storage_deposit.h"
         "models/outputs/unlock_conditions.h"
         "models/payloads/transaction.h"
         "models/payloads/tagged_data.h"
         "models/payloads/milestone.h"
         "models/message.h"
         #"models/signing.h"
         "models/unlock_block.h")

target_include_directories(iota_core PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CMAKE_INSTALL_PREFIX}/include")

add_dependencies(iota_core iota_crypto ext_uthash)

target_compile_options(iota_core PRIVATE -Wall -Wextra)

target_link_libraries(iota_core PUBLIC iota_crypto)

if(__JEMALLOC_INCLUDED)
  add_dependencies(iota_core jemalloc)
  target_link_libraries(iota_core PUBLIC jemalloc${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
  target_compile_definitions(iota_core PUBLIC USE_JEMALLOC)
  target_link_options(iota_core PUBLIC -Wl,--no-as-needed -ldl)
endif()

# install client lib and headers
install(TARGETS iota_core DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/core/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/core"
  FILES_MATCHING
  PATTERN "*.h")
