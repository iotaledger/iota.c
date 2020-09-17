# function for test cases
function(add_iota_test test_src test_name)
  add_executable(${test_name} "${test_src}")
  target_include_directories(${test_name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_INSTALL_PREFIX}/include)
  add_dependencies(${test_name} iota_client ext_unity)
  if(HAS_ASAN_ENABLED)
    target_link_libraries(${test_name} PRIVATE asan)
  endif()
  if(${test_src} MATCHES "^core")
    target_link_libraries(${test_name} PRIVATE iota_core unity)
  else()
    target_link_libraries(${test_name} PRIVATE iota_client unity)
  endif()
  add_test(${test_name} ${test_name})
endfunction(add_iota_test)

# core test cases #######
add_iota_test("core/test_address.c" core_address)
add_iota_test("core/test_balance.c" core_balance)
add_iota_test("core/test_inputs.c" core_inputs)
add_iota_test("core/test_outputs.c" core_outputs)
add_iota_test("core/test_iota_str.c" core_iota_str)

# client test cases #######
add_iota_test("client/test_http.c" client_http)
