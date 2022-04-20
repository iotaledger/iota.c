#[[
// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

# function for benchmark cases
function(add_iota_benchmark benchmark_name benchmark_src)
  add_executable(${benchmark_name} "${benchmark_src}")
  set_target_properties(${benchmark_name} PROPERTIES C_STANDARD_REQUIRED NO C_STANDARD 99)
  target_include_directories(${benchmark_name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/benchmark
                                                       ${CMAKE_INSTALL_PREFIX}/include)
  target_compile_options(${benchmark_name} PRIVATE -Wall -Wextra)
  # ASAN
  if(IOTA_ASAN_ENABLED)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      add_compile_options("-fsanitize=address,undefined,unsigned-integer-overflow" "-fsanitize-address-use-after-scope"
                          "-fno-omit-frame-pointer" "-fno-sanitize-recover=undefined,unsigned-integer-overflow")
      add_link_options("-fsanitize=address,undefined,unsigned-integer-overflow")
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
      add_compile_options("-fsanitize=address,undefined" "-fno-omit-frame-pointer" "-fsanitize-address-use-after-scope"
                          "-fno-sanitize-recover=undefined")
      add_link_options("-fsanitize=address,undefined")
    else()
      message(WARNING "Sanitizer is not supported on Windows or Release build")
    endif()
  endif()
  # mtrace
  if(ENABLE_MTRACE)
    target_compile_definitions(${benchmark_name} PRIVATE MTRACE_ENABLED)
  endif()
  if(${benchmark_src} MATCHES "^core")
    add_dependencies(${benchmark_name} iota_core)
    target_link_libraries(${benchmark_name} PRIVATE iota_core)
  elseif(${benchmark_src} MATCHES "^client")
    add_dependencies(${benchmark_name} iota_client)
    target_link_libraries(${benchmark_name} PRIVATE iota_client)
  elseif(${benchmark_src} MATCHES "^wallet")
    add_dependencies(${benchmark_name} iota_wallet)
    target_link_libraries(${benchmark_name} PRIVATE iota_wallet)
  endif()
  # install directory for benchmark application
  install(TARGETS ${benchmark_name} RUNTIME DESTINATION "${PROJECT_SOURCE_DIR}/benchmark")
endfunction(add_iota_benchmark)

add_iota_benchmark(benchmark_create_transaction_basic_output "core/create_transaction_basic_output.c")
add_iota_benchmark(benchmark_create_transaction_basic_output_full "core/create_transaction_basic_output_full.c")
add_iota_benchmark(benchmark_create_transaction_basic_output_max "core/create_transaction_basic_output_max.c")

if(WITH_IOTA_CLIENT)
  add_iota_benchmark(benchmark_send_tagged_data "client/send_tagged_data.c")
  add_iota_benchmark(benchmark_send_tagged_data_max "client/send_tagged_data_max.c")
endif()
