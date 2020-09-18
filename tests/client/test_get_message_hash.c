#include <stdio.h>
#include <unity/unity.h>

#include "client/api/get_message_hash.h"

void test_deser_message() {
  char const* const json_msg =
      "{\"data\":[{\"hash\":{\"msg_hash_a\":{\"version\":1,\"parent1\":"
      "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"parent2\":"
      "\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",\"payloadLength\":2,\"payload\":{\"type\":"
      "2,\"index\":\"5350414d\",\"data\":\"SGVsbG8gd29ybGQh\"}}}},{\"hash\":{\"msg_hash_a\":{\"version\":1,\"parent1\":"
      "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"parent2\":"
      "\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\",\"payloadLength\":1,\"payload\":{\"type\":"
      "2,\"index\":\"5350414d\",\"data\":\"SGVsbG8gd29ybGQh\"}}}}]}";
}

void test_deser_msg_err() {
  char const* const json_err = "{\"error\":{\"code\":400,\"message\":\"invalid data provided\"}}";
  res_msg_t* res_msg = res_msg_new();
  TEST_ASSERT_NOT_NULL(res_msg);

  int ret = deser_message_payload(json_err, res_msg);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT_EQUAL_STRING(res_msg->msg_u.error->msg, "invalid data provided");
  TEST_ASSERT_EQUAL_INT(res_msg->msg_u.error->code, 400);

  res_msg_free(res_msg);
}

int main() {
  UNITY_BEGIN();

  // RUN_TEST(test_deser_message);
  RUN_TEST(test_deser_msg_err);

  return UNITY_END();
}