#[[
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

# function for test cases
function(add_iota_test test_src test_name)
  add_executable(${test_name} "${test_src}")
  target_include_directories(${test_name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_INSTALL_PREFIX}/include)
  add_dependencies(${test_name} ext_unity)
  if(${test_src} MATCHES "^core")
    add_dependencies(${test_name} iota_core)
    target_link_libraries(${test_name} PRIVATE iota_core unity)
  elseif(${test_src} MATCHES "^crypto")
    add_dependencies(${test_name} iota_crypto)
    target_link_libraries(${test_name} PRIVATE iota_crypto unity)
  else()
    add_dependencies(${test_name} iota_client)
    target_link_libraries(${test_name} PRIVATE iota_client unity)
  endif()
  add_test(${test_name} ${test_name})
endfunction(add_iota_test)

# crypto test cases
add_custom_target(
  copy_test_vectors COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/crypto/ed25519_sign.input
                            ${CMAKE_CURRENT_BINARY_DIR})
add_iota_test("crypto/test_crypto.c" crypto_crypto)
add_dependencies(crypto_crypto copy_test_vectors)

# core test cases
add_iota_test("core/test_address.c" core_address)
add_iota_test("core/test_inputs.c" core_inputs)
add_iota_test("core/test_outputs.c" core_outputs)
add_iota_test("core/test_iota_str.c" core_iota_str)
if(__JEMALLOC_INCLUDED)
  add_iota_test("core/test_allocator.c" core_allocator)
endif()
add_iota_test("core/test_byte_buffer.c" core_byte_buffer)
add_iota_test("core/test_slip10.c" core_slip10)
add_iota_test("core/test_utils_bech32.c" core_utils_bech32)
add_iota_test("core/test_transaction.c" core_transaction)
add_iota_test("core/test_indexation.c" core_indexation)
add_iota_test("core/test_message.c" core_message)

# client test cases
add_iota_test("client/test_http.c" client_http)
add_iota_test("client/test_json.c" client_json)
add_iota_test("client/test_message_builder.c" client_message_builder)
add_iota_test("client/api_v1/test_get_info.c" client_get_info)
add_iota_test("client/api_v1/test_get_balance.c" client_get_balance)
add_iota_test("client/api_v1/test_response_error.c" client_res_error)
add_iota_test("client/api_v1/test_get_tips.c" client_get_tips)
add_iota_test("client/api_v1/test_outputs_from_address.c" client_output_from_addr)
add_iota_test("client/api_v1/test_get_output.c" client_get_output)
add_iota_test("client/api_v1/test_get_health.c" client_get_health)
add_iota_test("client/api_v1/test_get_message.c" client_get_message)
add_iota_test("client/api_v1/test_send_message.c" client_send_message)
add_iota_test("client/api_v1/test_find_message.c" client_find_message)
add_iota_test("client/api_v1/test_message_meta.c" client_message_meta)
add_iota_test("client/api_v1/test_message_children.c" client_message_children)

# for higher level APIs
add_executable(test_wallet_api "wallet/test_wallet.c")
target_include_directories(test_wallet_api PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_INSTALL_PREFIX}/include)
add_dependencies(test_wallet_api ext_unity iota_wallet)
target_link_libraries(test_wallet_api PRIVATE iota_wallet unity)
add_test(test_wallet_api test_wallet_api)
