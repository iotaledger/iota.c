# ########## IOTA Core library ################

add_library(iota_core STATIC)
# the required minimum C standard
set_target_properties(iota_core PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_core
  PRIVATE "core/address.c"
          "core/balance.c"
          "core/iota_str.c"
          "core/models/inputs/utxo_input.c"
          "core/models/outputs/sig_unlocked_single_deposit.c"
          "core/models/payloads/signed_transaction.c"
  PUBLIC  "core/address.h"
          "core/balance.h"
          "core/iota_str.h"
          "core/models/inputs/utxo_input.h"
          "core/models/outputs/sig_unlocked_single_deposit.h"
          "core/models/payloads/signed_transaction.h")

target_include_directories(iota_core PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CMAKE_INSTALL_PREFIX}/include")

add_dependencies(iota_core sodium ext_base58 ext_uthash)

target_link_libraries(iota_core INTERFACE base58 sodium)

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
  PUBLIC  "client/network/http_buffer.h"
          "client/network/http.h"
          "client/api/get_node_info.h"
          "client/api/json_utils.h"
          "client/api/response_error.h"
          "client/client_service.h")

target_include_directories(iota_client PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CURL_INCLUDE_DIRS}")

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
