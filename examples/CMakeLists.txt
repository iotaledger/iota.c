#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

# function for example cases
function(add_iota_example example_name example_src)
  add_executable(${example_name} "${example_src}")
  set_target_properties(${example_name} PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)
  target_include_directories(${example_name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_INSTALL_PREFIX}/include)
  target_compile_options(${example_name} PRIVATE -Wall -Wextra)
  if(IOTA_WALLET_ENABLE)
    add_dependencies(${example_name} iota_wallet)
    target_link_libraries(${example_name} PRIVATE iota_wallet)
  else()
    add_dependencies(${example_name} iota_client)
    target_link_libraries(${example_name} PRIVATE iota_client)
  endif()
endfunction(add_iota_example)

add_iota_example(encrypted_tagged_data_message "client/encrypted_tagged_data_message.c")
add_iota_example(tagged_data_message "client/tagged_data_message.c")
add_iota_example(get_message "client/get_message.c")
add_iota_example(node_info "client/node_info.c")

if(IOTA_WALLET_ENABLE)
  add_iota_example(send_basic_output "wallet/send_basic_output.c")
endif()

if(MQTT_CLIENT_ENABLE)
  add_iota_example(get_event_messages "client/get_event_messages.c")
endif()
