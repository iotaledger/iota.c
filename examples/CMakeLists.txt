#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

# function for example cases
function(add_iota_example example_name example_src)
  add_executable(${example_name} "${example_src}")
  set_target_properties(${example_name} PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)
  target_include_directories(${example_name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_INSTALL_PREFIX}/include)
  if(IOTA_WALLET_ENABLE)
    add_dependencies(${example_name} iota_wallet)
    target_link_libraries(${example_name} PRIVATE iota_wallet)
  else()
    add_dependencies(${example_name} iota_client)
    target_link_libraries(${example_name} PRIVATE iota_client)
  endif()
endfunction(add_iota_example)

add_iota_example(node_info "node_info.c")
add_iota_example(data_message "data_message.c")
add_iota_example(encrypted_data "encrypted_data.c")
add_iota_example(get_message "get_message.c")
if(IOTA_WALLET_ENABLE)
  add_iota_example(wallet_send_tx "wallet_send_tx.c")
  add_iota_example(wallet_get_balance "wallet_get_balance.c")
  add_iota_example(wallet_list_addresses "wallet_list_addresses.c")
endif()

if(MQTT_CLIENT_ENABLE)
  add_iota_example(get_mqtt_message "get_mqtt_message.c")
endif()