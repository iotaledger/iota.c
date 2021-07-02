// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/find_message.h"
#include "test_config.h"

void setUp(void) {}

void tearDown(void) {}

void test_find_msg_by_index() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_find_msg_t* res = res_find_msg_new();
  TEST_ASSERT(find_message_by_index(&ctx, "iota.c", res) == 0);
  TEST_ASSERT(res->is_error == false);
  res_find_msg_free(res);
  res = NULL;

  res = res_find_msg_new();
  TEST_ASSERT(find_message_by_index(&ctx, "iota.c\xF0\x9F\x80\x84", res) == 0);
  TEST_ASSERT(res->is_error == false);
  res_find_msg_free(res);
}

void test_deser_find_msg() {
  char const* const json_res =
      "{\"data\":{\"index\":\"iota.c\",\"maxResults\":1000,\"count\":7,\"messageIds\":["
      "\"2e8336769c77fb72afe861c6b4028887bceaeac47d2c4c17beb7a1e631b9b6b5\","
      "\"387a93c06865b7c0db19347b3e001e4406d3ad3423629e47cd919629b915263a\","
      "\"5e6dbe59bc1b0079482c131e86d80b6d573ac8c5854045ee43f3020cb278700d\","
      "\"6ed1b48f2e52f1c69fd0a6e44a76df7a5211588396ff13e8dad4edc2846e10aa\","
      "\"71d50b4ee518efcf535b379a21372110fe483ee07c6aff58d5ed67ee9b3ef069\","
      "\"b3773d9221b46f5d177b6da3f6acf1986471dddf121d7d900d2d70d8cb1b931e\","
      "\"f68b669107f05683e897efe5f2a3912c740280fbea0fcfd219bfd3409ba381ad\"]}}";

  res_find_msg_t* res = res_find_msg_new();

  TEST_ASSERT(deser_find_message(json_res, res) == 0);
  TEST_ASSERT_EQUAL_UINT32(1000, res->u.msg_ids->max_results);
  TEST_ASSERT_EQUAL_UINT32(7, res->u.msg_ids->count);
  TEST_ASSERT_EQUAL_UINT32(7, res_find_msg_get_id_len(res));
  TEST_ASSERT_EQUAL_STRING("387a93c06865b7c0db19347b3e001e4406d3ad3423629e47cd919629b915263a",
                           res_find_msg_get_id(res, 1));
  TEST_ASSERT_EQUAL_STRING("6ed1b48f2e52f1c69fd0a6e44a76df7a5211588396ff13e8dad4edc2846e10aa",
                           res_find_msg_get_id(res, 3));
  TEST_ASSERT_EQUAL_STRING("b3773d9221b46f5d177b6da3f6acf1986471dddf121d7d900d2d70d8cb1b931e",
                           res_find_msg_get_id(res, 5));
  TEST_ASSERT_NULL(res_find_msg_get_id(res, 7));

  res_find_msg_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_find_msg);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_find_msg_by_index);
#endif
  return UNITY_END();
}
