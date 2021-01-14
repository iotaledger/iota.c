// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/message_builder.h"

void test_msg_indexation() {
  char const* const exp_str =
      "{\"networkId\":null,\"parent1MessageId\":\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"parent2MessageId\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"payload\":{\"type\":"
      "2,\"index\":\"HELLO\",\"data\":\"48454C4C4F\"},\"nonce\":null}";

  indexation_t* idx = indexation_create("HELLO", "48454C4C4F");
  TEST_ASSERT_NOT_NULL(idx);
  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = 2;
  msg->pyaload = idx;

  char* str = message_to_json(msg);
  // printf("%s\n", str);
  TEST_ASSERT_NOT_NULL(str);
  TEST_ASSERT_EQUAL_STRING(exp_str, str);
  free(str);

  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_msg_indexation);

  return UNITY_END();
}