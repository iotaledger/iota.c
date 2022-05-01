#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

add_library(iota_client STATIC)
# the required minimum C standard
set_target_properties(iota_client PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)

target_sources(
  iota_client
  PRIVATE "network/http_curl.c"
          "api/json_parser/common.c"
          "api/json_parser/json_utils.c"
          "api/json_parser/message.c"
          "api/json_parser/unlock_blocks.c"
          "api/json_parser/inputs/inputs.c"
          "api/json_parser/outputs/feat_blocks.c"
          "api/json_parser/outputs/native_tokens.c"
          "api/json_parser/outputs/output_alias.c"
          "api/json_parser/outputs/output_basic.c"
          "api/json_parser/outputs/output_foundry.c"
          "api/json_parser/outputs/output_nft.c"
          "api/json_parser/outputs/outputs.c"
          "api/json_parser/outputs/unlock_conditions.c"
          "api/json_parser/payloads/payloads.c"
          "api/restful/get_node_info.c"
          "api/restful/response_error.c"
          "api/restful/get_tips.c"
          "api/restful/get_output.c"
          "api/restful/get_health.c"
          "api/restful/get_message_children.c"
          "api/restful/get_message_metadata.c"
          "api/restful/get_message.c"
          "api/restful/get_milestone.c"
          "api/restful/send_message.c"
          "api/restful/send_tagged_data.c"
          "api/restful/faucet_enqueue.c"
          "api/restful/get_outputs_id.c"
          "api/restful/get_transaction_included_message.c"
  PUBLIC "network/http.h"
         "client_service.h"
         "api/json_parser/json_utils.h"
         "api/json_parser/json_keys.h"
         "api/json_parser/common.h"
         "api/json_parser/message.h"
         "api/json_parser/unlock_blocks.h"
         "api/json_parser/inputs/inputs.h"
         "api/json_parser/outputs/feat_blocks.h"
         "api/json_parser/outputs/native_tokens.h"
         "api/json_parser/outputs/output_alias.h"
         "api/json_parser/outputs/output_basic.h"
         "api/json_parser/outputs/output_foundry.h"
         "api/json_parser/outputs/output_nft.h"
         "api/json_parser/outputs/outputs.h"
         "api/json_parser/outputs/unlock_conditions.h"
         "api/json_parser/payloads/payloads.h"
         "api/restful/get_node_info.h"
         "api/restful/response_error.h"
         "api/restful/get_tips.h"
         "api/restful/get_output.h"
         "api/restful/get_health.h"
         "api/restful/get_message_children.h"
         "api/restful/get_message_metadata.h"
         "api/restful/get_message.h"
         "api/restful/get_milestone.h"
         "api/restful/send_message.h"
         "api/restful/send_tagged_data.h"
         "api/restful/faucet_enqueue.h"
         "api/restful/get_outputs_id.h"
         "api/restful/get_transaction_included_message.h")

if(MQTT_CLIENT_ENABLE)
  target_sources(
    iota_client
    PRIVATE "network/mqtt/mqtt_mosquitto.c"
            "api/events/node_event.c"
            "api/events/sub_milestone_payload.c"
            "api/events/sub_messages_metadata.c"
            "api/events/sub_outputs_payload.c"
            "api/events/sub_serialized_output.c"
    PUBLIC "network/mqtt/mqtt.h"
           "api/events/node_event.h"
           "api/events/sub_milestone_payload.h"
           "api/events/sub_messages_metadata.h"
           "api/events/sub_outputs_payload.h"
           "api/events/sub_serialized_output.h")
endif()

target_include_directories(
  iota_client PUBLIC "${PROJECT_SOURCE_DIR}/src" "${CURL_INCLUDE_DIRS}"
                     "${CMAKE_INSTALL_PREFIX}/include/cjson" # for esp32 compatibility
)

add_dependencies(iota_client iota_core ext_cjson)

target_compile_options(iota_client PRIVATE -Wall -Wextra)

target_link_libraries(
  iota_client
  INTERFACE ${CURL_LIBRARIES} cjson
  PUBLIC iota_core)

if(MQTT_CLIENT_ENABLE)
  target_link_libraries(iota_client PRIVATE Threads::Threads)
  add_dependencies(iota_client ext_mosquitto)
  target_link_libraries(iota_client PUBLIC mosquitto_static)
endif()

# install client lib and headers
install(TARGETS iota_client DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(
  DIRECTORY "${PROJECT_SOURCE_DIR}/src/client/"
  DESTINATION "${CMAKE_INSTALL_PREFIX}/include/client"
  FILES_MATCHING
  PATTERN "*.h")
