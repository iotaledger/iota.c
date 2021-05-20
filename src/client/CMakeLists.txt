#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

add_library(iota_client STATIC)
# the required minimum C standard
set_target_properties(iota_client PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

add_dependencies(iota_client iota_core)

target_sources(
  iota_client
  PRIVATE "network/http_curl.c"
          "api/json_utils.c"
          "api/message.c"
          "api/message_builder.c"
          "api/v1/get_node_info.c"
          "api/v1/get_balance.c"
          "api/v1/response_error.c"
          "api/v1/get_tips.c"
          "api/v1/get_output.c"
          "api/v1/get_health.c"
          "api/v1/get_message_children.c"
          "api/v1/get_message_metadata.c"
          "api/v1/get_message.c"
          "api/v1/send_message.c"
          "api/v1/find_message.c"
          "api/v1/get_outputs_from_address.c"
  PUBLIC "network/http.h"
         "api/json_utils.h"
         "api/json_keys.h"
         "api/message.h"
         "api/message_builder.h"
         "api/v1/get_node_info.h"
         "api/v1/get_balance.h"
         "api/v1/response_error.h"
         "api/v1/get_tips.h"
         "api/v1/get_output.h"
         "api/v1/get_health.h"
         "api/v1/get_message_children.h"
         "api/v1/get_message_metadata.h"
         "api/v1/get_message.h"
         "api/v1/send_message.h"
         "api/v1/find_message.h"
         "api/v1/get_outputs_from_address.h"
         "client_service.h")

target_include_directories(
  iota_client PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CURL_INCLUDE_DIRS}"
                     "${CMAKE_INSTALL_PREFIX}/include/cjson" # for esp32 compatibility
)

add_dependencies(iota_client iota_core ext_cjson)

target_link_libraries(
  iota_client
  INTERFACE ${CURL_LIBRARIES} cjson
  PUBLIC iota_core)

# install client lib and headers
install(TARGETS iota_client DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/client/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/client"
  FILES_MATCHING
  PATTERN "*.h")
