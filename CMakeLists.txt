#[[
Copyright (c) 2019 IOTA Stiftung
https://github.com/iotaledger/iota.c

Refer to the LICENSE file for licensing information
]]

cmake_minimum_required(VERSION 3.11)

cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})

project(iota_client DESCRIPTION "IOTA Client Library")

enable_language(C)
enable_testing()

option(CCLIENT_TEST "Enable CClient library test cases" OFF)

# fetch iota_common
include(FetchContent)
FetchContent_Declare(
  iota_common
  GIT_REPOSITORY http://github.com/iotaledger/iota_common.git
  GIT_TAG 8cb88f3ff3188acc45457c80d47a369127ff9aaf
)

if(${CMAKE_VERSION} VERSION_LESS 3.14)
    macro(FetchContent_MakeAvailable NAME)
        FetchContent_GetProperties(${NAME})
        if(NOT ${NAME}_POPULATED)
            FetchContent_Populate(${NAME})
            add_subdirectory(${${NAME}_SOURCE_DIR} ${${NAME}_BINARY_DIR})
        endif()
    endmacro()
endif()

message(STATUS "Fetching iota_common")
FetchContent_MakeAvailable(iota_common)

# fetch external libs
include(ExternalProject)
include(cmake/cjson.cmake)
include(cmake/http_parser.cmake)
include(cmake/mbedtls.cmake)

# libs in the sandbox
link_directories("${CMAKE_INSTALL_PREFIX}/lib")

#==============cclient source=====================
set(API_CORE_DIR "cclient/api/core")
set(API_CORE_SRC
  ${API_CORE_DIR}/add_neighbors.c
  ${API_CORE_DIR}/attach_to_tangle.c
  ${API_CORE_DIR}/broadcast_transactions.c
  ${API_CORE_DIR}/check_consistency.c
  ${API_CORE_DIR}/core_init.c
  ${API_CORE_DIR}/find_transactions.c
  ${API_CORE_DIR}/get_balances.c
  ${API_CORE_DIR}/get_inclusion_states.c
  ${API_CORE_DIR}/get_neighbors.c
  ${API_CORE_DIR}/get_node_api_conf.c
  ${API_CORE_DIR}/get_node_info.c
  ${API_CORE_DIR}/get_tips.c
  ${API_CORE_DIR}/get_transactions_to_approve.c
  ${API_CORE_DIR}/get_trytes.c
  ${API_CORE_DIR}/logger.c
  ${API_CORE_DIR}/remove_neighbors.c
  ${API_CORE_DIR}/store_transactions.c
  ${API_CORE_DIR}/were_addresses_spent_from.c
)

set(API_EXTENDED_DIR "cclient/api/extended")
set(API_EXTENDED_SRC
  ${API_EXTENDED_DIR}/broadcast_bundle.c
  ${API_EXTENDED_DIR}/find_transaction_objects.c
  ${API_EXTENDED_DIR}/get_account_data.c
  ${API_EXTENDED_DIR}/get_bundle.c
  ${API_EXTENDED_DIR}/get_inputs.c
  ${API_EXTENDED_DIR}/get_latest_inclusion.c
  ${API_EXTENDED_DIR}/get_new_address.c
  ${API_EXTENDED_DIR}/get_transaction_objects.c
  ${API_EXTENDED_DIR}/is_promotable.c
  ${API_EXTENDED_DIR}/logger.c
  ${API_EXTENDED_DIR}/prepare_transfers.c
  ${API_EXTENDED_DIR}/promote_transaction.c
  ${API_EXTENDED_DIR}/replay_bundle.c
  ${API_EXTENDED_DIR}/send_transfer.c
  ${API_EXTENDED_DIR}/send_trytes.c
  ${API_EXTENDED_DIR}/store_and_broadcast.c
  ${API_EXTENDED_DIR}/traverse_bundle.c
)

set(HTTP_SRC 
  "cclient/http/http.c"
  "cclient/http/socket.c"
)

set(REQ_DIR "cclient/request")
set(REQ_SRC
  ${REQ_DIR}/add_neighbors.c
  ${REQ_DIR}/attach_to_tangle.c
  ${REQ_DIR}/broadcast_transactions.c
  ${REQ_DIR}/check_consistency.c
  ${REQ_DIR}/find_transactions.c
  ${REQ_DIR}/get_balances.c
  ${REQ_DIR}/get_inclusion_states.c
  ${REQ_DIR}/get_transactions_to_approve.c
  ${REQ_DIR}/get_trytes.c
  ${REQ_DIR}/remove_neighbors.c
  ${REQ_DIR}/store_transactions.c
  ${REQ_DIR}/were_addresses_spent_from.c
)

set(RES_DIR "cclient/response")
set(RES_SRC
  ${RES_DIR}/add_neighbors.c
  ${RES_DIR}/attach_to_tangle.c
  ${RES_DIR}/check_consistency.c
  ${RES_DIR}/error.c
  ${RES_DIR}/find_transactions.c
  ${RES_DIR}/get_balances.c
  ${RES_DIR}/get_inclusion_states.c
  ${RES_DIR}/get_missing_transactions.c
  ${RES_DIR}/get_neighbors.c
  ${RES_DIR}/get_node_info.c
  ${RES_DIR}/get_tips.c
  ${RES_DIR}/get_transactions_to_approve.c
  ${RES_DIR}/get_trytes.c
  ${RES_DIR}/remove_neighbors.c
  ${RES_DIR}/were_addresses_spent_from.c
)

set(JSON_SERIALIZER_DIR "cclient/serialization/json")
set(JSON_SERIALIZER_SRC
  ${JSON_SERIALIZER_DIR}/add_neighbors.c
  ${JSON_SERIALIZER_DIR}/attach_to_tangle.c
  ${JSON_SERIALIZER_DIR}/broadcast_transactions.c
  ${JSON_SERIALIZER_DIR}/check_consistency.c
  ${JSON_SERIALIZER_DIR}/error.c
  ${JSON_SERIALIZER_DIR}/find_transactions.c
  ${JSON_SERIALIZER_DIR}/get_balances.c
  ${JSON_SERIALIZER_DIR}/get_inclusion_states.c
  ${JSON_SERIALIZER_DIR}/get_missing_transactions.c
  ${JSON_SERIALIZER_DIR}/get_neighbors.c
  ${JSON_SERIALIZER_DIR}/get_node_api_conf.c
  ${JSON_SERIALIZER_DIR}/get_node_info.c
  ${JSON_SERIALIZER_DIR}/get_tips.c
  ${JSON_SERIALIZER_DIR}/get_transactions_to_approve.c
  ${JSON_SERIALIZER_DIR}/get_trytes.c
  ${JSON_SERIALIZER_DIR}/helpers.c
  ${JSON_SERIALIZER_DIR}/json_serializer.c
  ${JSON_SERIALIZER_DIR}/logger.c
  ${JSON_SERIALIZER_DIR}/remove_neighbors.c
  ${JSON_SERIALIZER_DIR}/store_transactions.c
  ${JSON_SERIALIZER_DIR}/were_addresses_spent_from.c
)

#==============end of cclient source=====================

# libcclient 
add_library(cclient 
  "cclient/service.c"
  ${API_CORE_SRC}
  ${API_EXTENDED_SRC}
  ${HTTP_SRC}
  ${REQ_SRC}
  ${RES_SRC}
  ${JSON_SERIALIZER_SRC}
)

add_dependencies(cclient
  "ext_cjson"
  "ext_http_parser"
  "ext_mbedtls"
  )

target_include_directories(cclient PUBLIC 
  "${PROJECT_SOURCE_DIR}"
  "${CMAKE_INSTALL_PREFIX}/include"
  "${CMAKE_INSTALL_PREFIX}/include/cjson"
  "${iota_common_SOURCE_DIR}"
)

set(IOTA_COMMON_LIBS common
  logger
  keccak
  mbedtls
  mbedcrypto
  mbedx509
)
target_link_libraries(cclient PUBLIC
  ${IOTA_COMMON_LIBS}
  cjson http_parser
)

install(TARGETS cclient DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
install(DIRECTORY "${PROJECT_SOURCE_DIR}/cclient/" DESTINATION "${CMAKE_INSTALL_PREFIX}/include/cclient" FILES_MATCHING PATTERN "*.h")

if(${CCLIENT_TEST})
  # ==============API test cases================
  function(add_cclient_test test_src test_name)
    add_executable(${test_name} "cclient/api/tests/${test_src}" "cclient/api/tests/cclient_service_init.c")
    target_include_directories(${test_name} PRIVATE
      "${PROJECT_SOURCE_DIR}"
      "${CMAKE_INSTALL_PREFIX}/include")
    add_dependencies(${test_name} cclient ext_unity)
    target_link_libraries(${test_name} PRIVATE 
      cclient 
      ${IOTA_COMMON_LIBS} 
      unity
    )
    add_test(${test_name} ${test_name})
  endfunction(add_cclient_test)

  add_cclient_test("test_add_neighbors.c" "test_add_neighbors")
  add_cclient_test("test_attach_to_tangle.c" "test_attach_to_tangle")
  add_cclient_test("test_broadcast_transactions.c" "test_broadcast_transactions")
  add_cclient_test("test_check_consistency.c" "test_check_consistency")
  add_cclient_test("test_find_transactions.c" "test_find_transactions")
  add_cclient_test("test_get_balances.c" "test_get_balances")
  add_cclient_test("test_get_inclusion_states.c" "test_get_inclusion_states")
  add_cclient_test("test_get_neighbors.c" "test_get_neighbors")
  add_cclient_test("test_get_node_api_conf.c" "test_get_node_api_conf")
  add_cclient_test("test_get_node_info.c" "test_get_node_info")
  add_cclient_test("test_get_tips.c" "test_get_tips")
  add_cclient_test("test_get_transactions_to_approve.c" "test_get_transactions_to_approve")
  add_cclient_test("test_get_trytes.c" "test_get_trytes")
  add_cclient_test("test_remove_neighbors.c" "test_remove_neighbors")
  add_cclient_test("test_store_transactions.c" "test_store_transactions")
  add_cclient_test("test_were_addresses_spent_from.c" "test_were_addresses_spent_from")
  # ==============API test cases================
endif()
