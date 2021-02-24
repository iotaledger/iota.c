// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/response_error.h"

void setUp(void) {}

void tearDown(void) {}

void test_deser_res_err() {
  char const* const json_err =
      "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"unable to handle the request\"}}";

  cJSON* json_obj = cJSON_Parse(json_err);
  TEST_ASSERT_NOT_NULL(json_obj);
  res_err_t* r = deser_error(json_obj);
  TEST_ASSERT_NOT_NULL(r);

  TEST_ASSERT_EQUAL_STRING("service_unavailable", r->code);
  TEST_ASSERT_EQUAL_STRING("unable to handle the request", r->msg);

  res_err_free(r);
  cJSON_Delete(json_obj);
}

void test_deser_err_msg_not_str() {
  char const* const json_err = "{ \"error\": { \"code\": 400, \"message\": 1234 } }";

  cJSON* json_obj = cJSON_Parse(json_err);
  TEST_ASSERT_NOT_NULL(json_obj);
  res_err_t* r = deser_error(json_obj);
  TEST_ASSERT_NULL(r);

  cJSON_Delete(json_obj);
}

void test_deser_err_not_obj() {
  char const* const json_err = "{ \"error\": \"invalid data provided\" }";

  cJSON* json_obj = cJSON_Parse(json_err);
  TEST_ASSERT_NOT_NULL(json_obj);
  res_err_t* r = deser_error(json_obj);
  TEST_ASSERT_NULL(r);

  cJSON_Delete(json_obj);
}

int main() {
  UNITY_BEGIN();

  // correct json format
  RUN_TEST(test_deser_res_err);
  // error message is not a string
  RUN_TEST(test_deser_err_msg_not_str);
  // error element not a json object
  RUN_TEST(test_deser_err_not_obj);

  return UNITY_END();
}
