// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/get_transaction_included_message.h"
#include "core/models/payloads/transaction.h"
#include "test_config.h"
#include "unity/unity.h"

/**
 * @brief This API has no deserialization tests because the response object is a block object which is tested in
 * test_get_block.c
 *
 */

void setUp(void) {}

void tearDown(void) {}

void test_get_transaction_included_block() {
  char const* const tx_id = "5e753f69b44870aa6a90adf2c366dccac00097c41d5c884dd81ef7cf29eefdd7";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_block_t* msg = res_block_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(get_transaction_included_block_by_id(&ctx, tx_id, msg) == 0);
  if (msg->is_error) {
    printf("API response: %s\n", msg->u.error->msg);
  } else {
    // It must be a transaction block
    TEST_ASSERT(core_block_get_payload_type(msg->u.blk) == CORE_BLOCK_PAYLOAD_TRANSACTION);
    // Print transaction block
    core_block_print((msg->u.blk), 0);
  }
  res_block_free(msg);
}

int main() {
  UNITY_BEGIN();
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_transaction_included_block);
#endif
  return UNITY_END();
}
