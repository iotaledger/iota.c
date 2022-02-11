// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/get_transaction_included_message.h"
#include "core/models/payloads/transaction.h"
#include "test_config.h"
#include "unity/unity.h"

/**
 * @brief This API has no deserialization tests because the respose object is a message object which is tested in
 * test_get_message.c
 *
 */

void setUp(void) {}

void tearDown(void) {}

void test_get_transaction_included_message() {
  char const* const tx_id = "0bbbc8cefce775e3adf9030089192b895af486c0030327cd14ae34132ad8df29";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(get_transaction_included_message_by_id(&ctx, tx_id, msg) == 0);
  if (msg->is_error) {
    printf("API response: %s\n", msg->u.error->msg);
  } else {
    // It must be a transaction message
    TEST_ASSERT(core_message_get_payload_type(msg->u.msg) == CORE_MESSAGE_PAYLOAD_TRANSACTION);
    // Print transaction message
    core_message_print((msg->u.msg), 0);
  }
  res_message_free(msg);
}

int main() {
  UNITY_BEGIN();
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_transaction_included_message);
#endif
  return UNITY_END();
}
