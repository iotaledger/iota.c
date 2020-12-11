// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_message.h"

void test_get_indexation() {
  char const* const msg_id = "e9e7e20cd3a626ea0166324ce202f24a5d3cec464b273ae4b986a188960e5cc2";
  iota_client_conf_t ctx = {
      .url = "http://localhost/",
      .port = 0  // use default port number
  };

  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(get_message_by_id(&ctx, msg_id, msg) == 0);
  TEST_ASSERT(msg->is_error == false);
  res_message_free(msg);
}

void test_deser_indexation() {
  char const* const idx_res =
      "{\"data\":{\"networkId\":\"6530425480034647824\",\"parent1MessageId\":"
      "\"f4ec1c1342e2003779e03c6c660315d8b69a0ce8ae60666e9642c4fb79a9c7ee\",\"parent2MessageId\":"
      "\"5c1b3e7ee5012d719ebc423f01f08e9c8812ecf3fb155ceeb931d4265f8faeed\",\"payload\":{\"type\":2,\"index\":\"Foo\","
      "\"data\":\"426172\"},\"nonce\":\"181571\"}}";
  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(deser_get_message(idx_res, msg) == 0);
  TEST_ASSERT(msg->is_error == false);
  TEST_ASSERT_EQUAL_STRING("6530425480034647824", msg->u.msg->net_id);
  TEST_ASSERT_EQUAL_STRING("181571", msg->u.msg->nonce);
  TEST_ASSERT_EQUAL_MEMORY("f4ec1c1342e2003779e03c6c660315d8b69a0ce8ae60666e9642c4fb79a9c7ee", msg->u.msg->parent1,
                           sizeof(msg->u.msg->parent1));
  TEST_ASSERT_EQUAL_MEMORY("5c1b3e7ee5012d719ebc423f01f08e9c8812ecf3fb155ceeb931d4265f8faeed", msg->u.msg->parent2,
                           sizeof(msg->u.msg->parent2));
  TEST_ASSERT(msg->u.msg->type == MSG_INDEXATION);
  payload_index_t* idx = (payload_index_t*)msg->u.msg->payload;
  TEST_ASSERT_EQUAL_STRING("Foo", idx->index->data);
  TEST_ASSERT_EQUAL_STRING("426172", idx->data->data);

  res_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_indexation);
  // RUN_TEST(test_get_indexation);

  return UNITY_END();
}
