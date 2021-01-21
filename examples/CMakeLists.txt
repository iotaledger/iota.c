#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

# function for example cases
function(add_iota_example example_name example_src)
  add_executable(${example_name} "${example_src}")
  set_target_properties(${example_name} PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)
  target_include_directories(${example_name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_INSTALL_PREFIX}/include)
  add_dependencies(${example_name} iota_wallet)
  target_link_libraries(${example_name} PRIVATE iota_wallet)
endfunction(add_iota_example)

add_iota_example(wallet_send_tx "wallet_send_tx.c")
add_iota_example(send_index "send_indexation_msg.c")
