// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/restful/get_message.h"
#include "client/api/restful/send_message.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "crypto/iota_crypto.h"
#include "test_config.h"

#define TAG_TAG_LEN 14
#define TAG_DATA_LEN 64
char const* const tag = "IOTA TEST DATA";

void setUp(void) {}

void tearDown(void) {}

void test_deser_send_msg_response() {
  char const* const str_res = "{\"messageId\":\"322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5\"}";
  char const* const msg_id = "322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5";
  res_send_message_t res = {};

  TEST_ASSERT(deser_send_message_response(str_res, &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  TEST_ASSERT_EQUAL_STRING(msg_id, res.u.msg_id);
}

void test_send_core_message_tagged_data() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);

  // Create tagged data payload
  tagged_data_t* tagged_data = tagged_data_create((byte_t*)tag, TAG_TAG_LEN, tag_data, TAG_DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_print(tagged_data, 0);

  // Create a core message object
  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  msg->network_id = 0;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TAGGED;
  msg->payload = tagged_data;
  msg->nonce = 0;

  res_send_message_t res = {};
  res.is_error = false;

  // Test NULL Input Parameters
  TEST_ASSERT_EQUAL_INT(-1, send_core_message(NULL, msg, &res));
  TEST_ASSERT_EQUAL_INT(-1, send_core_message(&ctx, NULL, &res));
  TEST_ASSERT_EQUAL_INT(-1, send_core_message(&ctx, msg, NULL));

  TEST_ASSERT_EQUAL_INT(0, send_core_message(&ctx, msg, &res));
  TEST_ASSERT(res.is_error == false);

  printf("Message ID: %s\n", res.u.msg_id);
  core_message_free(msg);

  // Get message by message id
  res_message_t* msg_res = res_message_new();
  TEST_ASSERT_NOT_NULL(msg_res);
  TEST_ASSERT_EQUAL_INT(0, get_message_by_id(&ctx, res.u.msg_id, msg_res));

  // Get tagged data payload from message response
  tagged_data_t* tagged_data_res = (tagged_data_t*)msg_res->u.msg->payload;

  // Check if tag in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->tag->data, (byte_t*)tag, TAG_TAG_LEN);

  // Check if data in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->data->data, tag_data, TAG_DATA_LEN);
  res_message_free(msg_res);
}

/* TODO, send transaction on private tangle
void test_send_core_message_tx() {
  iota_client_conf_t ctx = {
      .host = "localhost",
      .port = 14265  // use default port number
  };

  // genrate ed25519 address

  // request found from faucet

  // create address unlock condition

  // compose basic output

  // send out message
}
*/

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_send_msg_response);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_send_core_message_tagged_data);
#endif
  // send transaction on alphanet
  // RUN_TEST(test_send_core_message_tx);

  return UNITY_END();
}
