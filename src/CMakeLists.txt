# ########## IOTA Core library ################

add_library(iota_core STATIC)
# the required minimum C standard
set_target_properties(iota_core PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_core
  PRIVATE "core/address.c"
          "core/balance.c"
          "core/utils/iota_str.c"
          "core/models/inputs/utxo_input.c"
          "core/models/outputs/sig_unlocked_single_deposit.c"
          "core/models/payloads/signed_transaction.c"
  PUBLIC "core/address.h"
         "core/balance.h"
         "core/utils/iota_str.h"
         "core/models/inputs/utxo_input.h"
         "core/models/outputs/sig_unlocked_single_deposit.h"
         "core/models/payloads/signed_transaction.h")

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
  PATTERN "*.h")

# ########## IOTA Client library ################

add_library(iota_client STATIC)
# the required minimum C standard
set_target_properties(iota_client PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_client
  PRIVATE "client/network/http_buffer.c"
          "client/network/http_curl.c"
          "client/api/get_node_info.c"
          "client/api/json_utils.c"
          "client/api/response_error.c"
          "client/api/get_message_hash.c"
          "client/api/get_tips.c"
  PUBLIC "client/network/http_buffer.h"
         "client/network/http.h"
         "client/api/get_node_info.h"
         "client/api/json_utils.h"
         "client/api/response_error.h"
         "client/api/get_message_hash.h"
         "client/api/get_tips.h"
         "client/client_service.h")

target_include_directories(iota_client PUBLIC
  "${PROJECT_SOURCE_DIR}/src"
  "${CURL_INCLUDE_DIRS}"
  "${CMAKE_INSTALL_PREFIX}/include/cjson" # for esp32 compatibility
)

add_dependencies(iota_client iota_core ext_cjson)

target_link_libraries(
  iota_client
  INTERFACE ${CURL_LIBRARIES} cjson
  PUBLIC iota_core)

if(HAS_ASAN_ENABLED)
  target_link_libraries(iota_client PRIVATE asan)
endif()

# install client lib and headers
install(TARGETS iota_client DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/client/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/client"
  FILES_MATCHING
  PATTERN "*.h")
