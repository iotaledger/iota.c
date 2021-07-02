// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/v1/get_tips.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_tips() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);
  TEST_ASSERT(get_tips(&ctx, res_tips) == 0);
  if (res_tips->is_error == true) {
    printf("Error: %s\n", res_tips->u.error->msg);
  } else {
    TEST_ASSERT(get_tips_id_count(res_tips) > 0);
  }
  res_tips_free(res_tips);
}

void test_deser_get_tips() {
  char const* const json_tips =
      "{\"data\":{\"tipMessageIds\":[\"0a7c22aa43620d938146bcfc94a40804b26a5aaf3913bdc51b2836c47650de5c\","
      "\"3a3ca52a4c7d96fed4eef037db4421231f09e63a817bcf913f33c0806e565de9\","
      "\"a714ca72bb21d1e69b49a272713b9a1edc4d5679695680b5f36b907c0ed0d445\","
      "\"ea878b98a3eb38154993ea27d597e6cbb8fda0cd7b71cc2eb345b6c62140a6bf\"]}}";

  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);
  TEST_ASSERT(deser_get_tips(json_tips, res_tips) == 0);
  TEST_ASSERT(res_tips->is_error == false);
  TEST_ASSERT_EQUAL_INT(4, get_tips_id_count(res_tips));
  TEST_ASSERT_EQUAL_MEMORY("0a7c22aa43620d938146bcfc94a40804b26a5aaf3913bdc51b2836c47650de5c", get_tips_id(res_tips, 0),
                           STR_TIP_MSG_ID_LEN);
  TEST_ASSERT_EQUAL_MEMORY("3a3ca52a4c7d96fed4eef037db4421231f09e63a817bcf913f33c0806e565de9", get_tips_id(res_tips, 1),
                           STR_TIP_MSG_ID_LEN);
  TEST_ASSERT_EQUAL_MEMORY("a714ca72bb21d1e69b49a272713b9a1edc4d5679695680b5f36b907c0ed0d445", get_tips_id(res_tips, 2),
                           STR_TIP_MSG_ID_LEN);
  TEST_ASSERT_EQUAL_MEMORY("ea878b98a3eb38154993ea27d597e6cbb8fda0cd7b71cc2eb345b6c62140a6bf", get_tips_id(res_tips, 3),
                           STR_TIP_MSG_ID_LEN);
  res_tips_free(res_tips);
}

void test_deser_tips_err() {
  char const* const json_err =
      "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"unable to handle the request\"}}";

  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);
  TEST_ASSERT(deser_get_tips(json_err, res_tips) == 0);
  TEST_ASSERT(res_tips->is_error == true);
  TEST_ASSERT_EQUAL_STRING(res_tips->u.error->code, "service_unavailable");
  TEST_ASSERT_EQUAL_STRING(res_tips->u.error->msg, "unable to handle the request");
  res_tips_free(res_tips);
}

int main() {
  UNITY_BEGIN();

#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_tips);
#endif
  RUN_TEST(test_deser_get_tips);
  RUN_TEST(test_deser_tips_err);

  return UNITY_END();
}