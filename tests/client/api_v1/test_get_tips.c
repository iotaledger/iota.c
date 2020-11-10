#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_tips.h"

void test_get_tips() {
  iota_client_conf_t ctx = {
      .url = "https://virtserver.swaggerhub.com/oopsmonk/mytest/0.0.1/",
      .port = 0  // use default port number
  };
  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);

  int ret = get_tips(&ctx, res_tips);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT(res_tips->is_error == false);

  res_tips_free(res_tips);
}

void test_deser_get_tips() {
  char const* const json_tips =
      "{\"data\":{\"tip1MessageId\":\"42e089e73926b1b3dbf222ef2aea565645f442bc9ff74d0a86531ad6736882e2\","
      "\"tip2MessageId\":\"ad2f6b896fc9ae6bd8b675a7c01ed53e389d406efd09b1f66a03b31c32240bd1\"}}";

  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);

  int ret = deser_get_tips(json_tips, res_tips);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res_tips->is_error == false);
  TEST_ASSERT_EQUAL_MEMORY("42e089e73926b1b3dbf222ef2aea565645f442bc9ff74d0a86531ad6736882e2",
                           res_tips->tips_u.tips.tip1, STR_TIP_MSG_LEN);
  TEST_ASSERT_EQUAL_MEMORY("ad2f6b896fc9ae6bd8b675a7c01ed53e389d406efd09b1f66a03b31c32240bd1",
                           res_tips->tips_u.tips.tip2, STR_TIP_MSG_LEN);

  res_tips_free(res_tips);
}

void test_deser_tips_err() {
  char const* const json_err =
      "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"unable to handle the request\"}}";
  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);

  int ret = deser_get_tips(json_err, res_tips);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res_tips->is_error == true);
  TEST_ASSERT_EQUAL_STRING(res_tips->tips_u.error->code, "service_unavailable");
  TEST_ASSERT_EQUAL_STRING(res_tips->tips_u.error->msg, "unable to handle the request");

  res_tips_free(res_tips);
}

int main() {
  UNITY_BEGIN();

  // RUN_TEST(test_get_tips);
  RUN_TEST(test_deser_get_tips);
  RUN_TEST(test_deser_tips_err);

  return UNITY_END();
}