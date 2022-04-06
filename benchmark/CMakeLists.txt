#[[
// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

# function for benchmark cases
function(add_iota_benchmark benchmark_name benchmark_src)
  add_executable(${benchmark_name} "${benchmark_src}")
  set_target_properties(${benchmark_name} PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)
  target_include_directories(${benchmark_name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_INSTALL_PREFIX}/include)
  target_compile_options(${benchmark_name} PRIVATE -Wall -Wextra)
  if(IOTA_WALLET_ENABLE)
    add_dependencies(${benchmark_name} iota_wallet)
    target_link_libraries(${benchmark_name} PRIVATE iota_wallet)
  elseif(WITH_IOTA_CLIENT)
    add_dependencies(${benchmark_name} iota_client)
    target_link_libraries(${benchmark_name} PRIVATE iota_client)
  else()
    add_dependencies(${benchmark_name} iota_core)
    target_link_libraries(${benchmark_name} PRIVATE iota_core)
  endif()
  # install directory for benchmark application
  install(TARGETS ${benchmark_name} RUNTIME DESTINATION "${PROJECT_SOURCE_DIR}/benchmark")
endfunction(add_iota_benchmark)

if(WITH_IOTA_CLIENT)
  add_iota_benchmark(benchmark_send_tagged_data "client/send_tagged_data.c")
endif()
