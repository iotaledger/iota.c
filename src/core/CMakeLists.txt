#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

add_library(iota_core STATIC)
# the required minimum C standard
set_target_properties(iota_core PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

add_dependencies(iota_core iota_crypto)

target_sources(
  iota_core
  PRIVATE "address.c"
          "seed.c"
          "utils/iota_str.c"
          "utils/byte_buffer.c"
          "utils/slip10.c"
          "utils/bech32.c"
          "models/inputs/utxo_input.c"
          "models/outputs/outputs.c"
          "models/payloads/transaction.c"
          "models/payloads/indexation.c"
          "models/message.c"
  PUBLIC "address.h"
         "seed.c"
         "utils/iota_str.h"
         "utils/byte_buffer.h"
         "utils/slip10.h"
         "utils/bech32.h"
         "models/inputs/utxo_input.h"
         "models/outputs/outputs.h"
         "models/payloads/transaction.h"
         "models/payloads/indexation.h"
         "models/message.h")

target_include_directories(iota_core PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CMAKE_INSTALL_PREFIX}/include")

add_dependencies(iota_core ext_uthash)

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
