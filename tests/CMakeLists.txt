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
  else()
    add_dependencies(${test_name} iota_client)
    target_link_libraries(${test_name} PRIVATE iota_client unity)
  endif()
  add_test(${test_name} ${test_name})
endfunction(add_iota_test)

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

# client test cases
add_iota_test("client/test_http.c" client_http)
add_iota_test("client/test_json.c" client_json)
add_iota_test("client/api_v1/test_get_info.c" client_get_info)
add_iota_test("client/api_v1/test_response_error.c" client_res_error)
add_iota_test("client/api_v1/test_get_tips.c" client_get_tips)
