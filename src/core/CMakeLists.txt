add_library(iota_core STATIC)
# the required minimum C standard
set_target_properties(iota_core PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_core
  PRIVATE "address.c"
          "balance.c"
          "utils/iota_str.c"
          "utils/byte_buffer.c"
          "models/inputs/utxo_input.c"
          "models/outputs/sig_unlocked_single_deposit.c"
          "models/payloads/signed_transaction.c"
  PUBLIC "address.h"
         "balance.h"
         "utils/iota_str.h"
         "utils/byte_buffer.h"
         "models/inputs/utxo_input.h"
         "models/outputs/sig_unlocked_single_deposit.h"
         "models/payloads/signed_transaction.h")

target_include_directories(iota_core PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CMAKE_INSTALL_PREFIX}/include")

add_dependencies(iota_core sodium ext_base58 ext_uthash)

target_link_libraries(iota_core INTERFACE base58 sodium)

if(__JEMALLOC_INCLUDED)
  add_dependencies(iota_core jemalloc)
  target_link_libraries(iota_core PUBLIC jemalloc${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
  target_compile_definitions(iota_core PUBLIC USE_JEMALLOC)
  target_link_options(iota_core PUBLIC -Wl,--no-as-needed -ldl)
endif()

if(HAS_ASAN_ENABLED)
  target_link_libraries(iota_core PRIVATE asan)
endif()

# install client lib and headers
install(TARGETS iota_core DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/core/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/core"
  FILES_MATCHING
  PATTERN "*.h"
)
