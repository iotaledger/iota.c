// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "client/api/restful/send_message.h"
#include "core/utils/byte_buffer.h"

#include "core/address.h"

void setUp(void) {}

void tearDown(void) {}

#if 0  // FIXME
void test_send_indexation() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_send_message_t res = {};
  TEST_ASSERT(send_indexation_msg(&ctx, "iota.c", "Hello IOTA", &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  printf("message ID: %s\n", res.u.msg_id);
}

void test_send_core_message_indexation() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t idx_data[12] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
  indexation_t* idx = indexation_create("iota.c", idx_data, sizeof(idx_data));
  TEST_ASSERT_NOT_NULL(idx);
  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = 2;
  msg->payload = idx;

  res_send_message_t res = {};
  TEST_ASSERT(send_core_message(&ctx, msg, &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  printf("message ID: %s\n", res.u.msg_id);

  core_message_free(msg);
}

void test_serialize_indexation() {
  char const* const p1 = "7f471d9bb0985e114d78489cfbaf1fb3896931bdc03c89935bacde5b9fbc86ff";
  char const* const p2 = "3b4354521ade76145b5616a414fa283fcdb7635ee627a42ecb2f75135e18f10f";
  char const* const data = "Hello";
  char const* const index = "iota.c";
  char const* const exp_msg =
      "{\"networkId\":\"\",\"parentMessageIds\":[\"7f471d9bb0985e114d78489cfbaf1fb3896931bdc03c89935bacde5b9fbc86ff\","
      "\"3b4354521ade76145b5616a414fa283fcdb7635ee627a42ecb2f75135e18f10f\"],\"payload\":{\"type\":2,\"index\":"
      "\"696F74612E63\",\"data\":\"48656C6C6F\"},\"nonce\":\"\"}";

  message_t* msg = api_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  payload_index_t* idx = payload_index_new();
  TEST_ASSERT_NOT_NULL(idx);
  TEST_ASSERT_TRUE(byte_buf_append(idx->data, (byte_t const*)data, strlen(data) + 1));
  TEST_ASSERT_TRUE(byte_buf_append(idx->index, (byte_t const*)index, strlen(index) + 1));
  msg->type = MSG_PAYLOAD_INDEXATION;
  msg->payload = idx;

  api_message_add_parent(msg, p1);
  api_message_add_parent(msg, p2);
  TEST_ASSERT_EQUAL_INT(2, api_message_parent_count(msg));

  byte_buf_t* message_string = byte_buf_new();
  TEST_ASSERT_NOT_NULL(message_string);
  TEST_ASSERT(serialize_indexation(msg, message_string) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_msg, message_string->data);

  api_message_free(msg);
  byte_buf_free(message_string);
}

void test_deser_send_msg_response() {
  char const* const str_res =
      "{\"data\":{\"messageId\":\"322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5\"}}";
  char const* const exp_id = "322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5";
  res_send_message_t res = {};

  TEST_ASSERT(deser_send_message_response(str_res, &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  TEST_ASSERT_EQUAL_STRING(exp_id, res.u.msg_id);
}
#endif

// TODO, send transaction on private tangle
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

int main() {
  UNITY_BEGIN();

  // RUN_TEST(test_serialize_indexation);
  // RUN_TEST(test_deser_send_msg_response);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_send_indexation);
  RUN_TEST(test_send_core_message_indexation);
#endif
  // send transaction on alphanet
  RUN_TEST(test_send_core_message_tx);

  return UNITY_END();
}
