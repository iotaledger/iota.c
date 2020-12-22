// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/send_message.h"

void test_send_indexation() {
  iota_client_conf_t ctx = {
      .url = "https://iota-node/",
      .port = 0  // use default port number
  };

  res_send_message_t res = {};
  TEST_ASSERT(send_indexation_msg(&ctx, "iota.c", "Hello IOTA", &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  printf("message ID: %s\n", res.u.msg_id);
}

void test_serialize_indexation() {
  char const* const p1 = "7f471d9bb0985e114d78489cfbaf1fb3896931bdc03c89935bacde5b9fbc86ff";
  char const* const p2 = "3b4354521ade76145b5616a414fa283fcdb7635ee627a42ecb2f75135e18f10f";
  char const* const data = "Hello";
  char const* const index = "iota.c";
  char const* const exp_msg =
      "{\"networkId\":\"\",\"parent1MessageId\":\"7f471d9bb0985e114d78489cfbaf1fb3896931bdc03c89935bacde5b9fbc86ff\","
      "\"parent2MessageId\":\"3b4354521ade76145b5616a414fa283fcdb7635ee627a42ecb2f75135e18f10f\",\"payload\":{\"type\":"
      "2,\"index\":\"iota.c\",\"data\":\"48656C6C6F\"},\"nonce\":\"\"}";

  message_t* msg = api_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  payload_index_t* idx = payload_index_new();
  TEST_ASSERT_NOT_NULL(idx);
  TEST_ASSERT_TRUE(byte_buf_append(idx->data, (byte_t const*)data, strlen(data) + 1));
  TEST_ASSERT_TRUE(byte_buf_append(idx->index, (byte_t const*)index, strlen(index) + 1));
  msg->type = MSG_PAYLOAD_INDEXATION;
  msg->payload = idx;
  memcpy(msg->parent1, p1, sizeof(msg->parent1));
  memcpy(msg->parent2, p2, sizeof(msg->parent2));
  TEST_ASSERT_EQUAL_STRING(p1, msg->parent1);
  TEST_ASSERT_EQUAL_STRING(p2, msg->parent2);

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

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_serialize_indexation);
  RUN_TEST(test_deser_send_msg_response);
  // RUN_TEST(test_send_indexation);

  return UNITY_END();
}
