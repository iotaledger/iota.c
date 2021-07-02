// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_message_children.h"
#include "test_config.h"

void setUp(void) {}

void tearDown(void) {}

void test_deser_message_children() {
  char const* const json_res =
      "{\"data\":{\"messageId\":\"a30d95e791d9cefa52156051974d5396d48b517bd16644bf2d3d0f67e9f7d82f\",\"maxResults\":"
      "1000,\"count\":4,\"childrenMessageIds\":[\"38c01ac57bef2407ba38900c0d78b1d7a0e51d78feb08fff14606024f5077048\","
      "\"7822b722efb52af2e127aa79a1d16698ce00412ed1e38d4bcea6394e7f512828\","
      "\"ad7ab203440f3183034e18545c6708ffe820ce519757d3a3ebcf89fcde03af4d\","
      "\"f63d38f0e10b65234824bbeb0fd0917b890089a8cc9cc2ddef22879b1785309d\"]}}";

  res_msg_children_t* ch = res_msg_children_new();
  TEST_ASSERT_NOT_NULL(ch);

  int ret = deser_msg_children(json_res, ch);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(ch->is_error);
  TEST_ASSERT(ch->u.data->count == 4);
  TEST_ASSERT(ch->u.data->max_results == 1000);
  TEST_ASSERT_EQUAL_STRING("a30d95e791d9cefa52156051974d5396d48b517bd16644bf2d3d0f67e9f7d82f", ch->u.data->msg_id);
  TEST_ASSERT_EQUAL_INT(ch->u.data->count, res_msg_children_len(ch));
  TEST_ASSERT_EQUAL_STRING("38c01ac57bef2407ba38900c0d78b1d7a0e51d78feb08fff14606024f5077048",
                           res_msg_children_get(ch, 0));
  TEST_ASSERT_EQUAL_STRING("f63d38f0e10b65234824bbeb0fd0917b890089a8cc9cc2ddef22879b1785309d",
                           res_msg_children_get(ch, 3));
  res_msg_children_free(ch);
}

void test_get_msg_children() {
  char const* const msg_id = "b3546cd9ab475b9b271a0e57041def4b7a2e6e67c9e59c835cc897e19f149a56";

  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};
  res_msg_children_t* ch = res_msg_children_new();
  TEST_ASSERT_NOT_NULL(ch);

  TEST_ASSERT(get_message_children(&ctx, msg_id, ch) == 0);
  if (ch->is_error) {
    TEST_ASSERT_NOT_NULL(ch->u.error);
    printf("Error response: %s\n", ch->u.error->msg);
  } else {
    TEST_ASSERT_NOT_NULL(ch->u.data);
    printf("Message ID: %s, max results: %d, count: %d\n", ch->u.data->msg_id, ch->u.data->max_results,
           ch->u.data->count);

    size_t ch_num = res_msg_children_len(ch);
    printf("%zu children:\n", ch_num);
    TEST_ASSERT(ch->u.data->count == ch_num);
    for (size_t i = 0; i < ch_num; i++) {
      printf("\t%s\n", res_msg_children_get(ch, i));
    }
  }

  res_msg_children_free(ch);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_message_children);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_msg_children);
#endif

  return UNITY_END();
}