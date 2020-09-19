#include <stdio.h>
#include <unity/unity.h>

#include "client/api/get_tips.h"

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
  TEST_ASSERT_EQUAL_MEMORY("f532a53545103276b46876c473846d98648ee418468bce76df4868648dd73e5d",
                           res_tips->tips_u.tips.tip1, TIP_HASH_BYTES);
  TEST_ASSERT_EQUAL_MEMORY("78d546b46aec4557872139a48f66bc567687e8413578a14323548732358914a2",
                           res_tips->tips_u.tips.tip2, TIP_HASH_BYTES);

  res_tips_free(res_tips);
}

void test_deser_get_tips() {
  char const* const json_tips =
      "{\"data\":{\"tip1\":\"f532a53545103276b46876c473846d98648ee418468bce76df4868648dd73e5d\",\"tip2\":"
      "\"78d546b46aec4557872139a48f66bc567687e8413578a14323548732358914a2\"}}";

  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);

  int ret = deser_get_tips(json_tips, res_tips);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res_tips->is_error == false);
  TEST_ASSERT_EQUAL_MEMORY("f532a53545103276b46876c473846d98648ee418468bce76df4868648dd73e5d",
                           res_tips->tips_u.tips.tip1, TIP_HASH_BYTES);
  TEST_ASSERT_EQUAL_MEMORY("78d546b46aec4557872139a48f66bc567687e8413578a14323548732358914a2",
                           res_tips->tips_u.tips.tip2, TIP_HASH_BYTES);

  res_tips_free(res_tips);
}

void test_deser_tips_err() {
  char const* const json_err = "{\"error\":{\"code\":404,\"message\":\"can not find data\"}}";
  res_tips_t* res_tips = res_tips_new();
  TEST_ASSERT_NOT_NULL(res_tips);

  int ret = deser_get_tips(json_err, res_tips);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT_EQUAL_STRING(res_tips->tips_u.error->msg, "can not find data");
  TEST_ASSERT_EQUAL_INT(res_tips->tips_u.error->code, 404);

  res_tips_free(res_tips);
}

int main() {
  UNITY_BEGIN();

  // RUN_TEST(test_get_tips);
  RUN_TEST(test_deser_get_tips);
  RUN_TEST(test_deser_tips_err);

  return UNITY_END();
}