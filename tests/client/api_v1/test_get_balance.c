// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unity/unity.h>

#include "client/api/v1/get_balance.h"
#include "core/utils/byte_buffer.h"

#define ADDR_HEX "7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006"
#define ADDR_INV "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

void test_get_balance() {
  iota_client_conf_t conf = {
      .url = "http://0.0.0.0/",
      .port = 14265  // use default port number
  };

  res_balance_t* res = res_balance_new();

  // test null cases
  TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, res));

  // reset
  res->is_error = false;

  // test invalid address
  TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, ADDR_INV, res));
  TEST_ASSERT_EQUAL_STRING(
      "bad request, error: invalid address: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx, error: "
      "encoding/hex: invalid byte: U+0078 'x': invalid parameter",
      res->u.error->msg);

  // reset
  res->is_error = false;

  // test for success
  TEST_ASSERT_EQUAL_INT(0, get_balance(&conf, ADDR_HEX, res));
}

void test_deser_balance_info() {
  char const* json_info_200 =
      "{\"data\":{\"address\": \"7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006\","
      "\"maxResults\": 1000,"
      "\"count\": 25,"
      "\"balance\": 1338263}}";

  char const* json_info_400 =
      "{\"error\": {"
      "\"code\": \"400\", "
      "\"message\": \"bad request, error: invalid address: 0, error: encoding/hex: odd length hex string: invalid "
      "parameter\"}}";

  // test http status code 200
  res_balance_t* res = res_balance_new();
  TEST_ASSERT_EQUAL_INT(0, deser_balance_info(json_info_200, res));
  TEST_ASSERT_EQUAL_INT(1000, res->u.output_balance->max_results);
  TEST_ASSERT_EQUAL_INT(25, res->u.output_balance->count);
  TEST_ASSERT_EQUAL_INT(1338263, res->u.output_balance->balance);

  // test http status code 400
  TEST_ASSERT_EQUAL_INT(-1, deser_balance_info(json_info_400, res));
  TEST_ASSERT(res->is_error);
  TEST_ASSERT_EQUAL_STRING("400", res->u.error->code);
  TEST_ASSERT_EQUAL_STRING(
      "bad request, error: invalid address: 0, error: encoding/hex: odd length hex string: invalid parameter",
      res->u.error->msg);

  // reset res->is_error to false;
  res->is_error = false;

  res_balance_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_balance_info);
  // RUN_TEST(test_get_balance);

  return UNITY_END();
}
