// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unity/unity.h>

#include "client/api/v1/get_balance.h"
#include "core/utils/byte_buffer.h"

#define ADDR_HEX "7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006"

void test_get_balance() {
  iota_client_conf_t conf = {
      .url = "http://0.0.0.0",
      .port = 14265  // use default port number
  };

  res_balance_t *res = calloc(1, sizeof(res_balance_t));
  byte_t addr[IOTA_ADDRESS_BYTES];

  // convert hex2bin
  TEST_ASSERT_EQUAL_INT(0, hex2bin(ADDR_HEX, addr + 1, IOTA_ADDRESS_BYTES - 1));

  // Ed25519 address
  addr[0] = 0x0001;

  // test null cases
  TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, res));

  // test for success
  TEST_ASSERT_EQUAL_INT(0, get_balance(&conf, addr, res));
}

void test_deser_balance_info() {
  char const* json_info_200 =
      "{\"data\":{\"address\": \"7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006\","
      "\"maxResults\": 1000,"
      "\"count\": 25,"
      "\"balance\": 1338263}}";

  res_balance_t *res = calloc(1, sizeof(res_balance_t));
//
//  char const* json_info_400 =
//      "{\"error\": {"
//      "\"code\": \"invalid_data, "
//      "\"message\": \"invalid data provided\"}}";
//
//  char const* json_info_404 =
//      "{\"error\": {"
//      "{\"code\": \"not_found\""
//      "{\"message\": \"could not find data\"}}"

  TEST_ASSERT_EQUAL_INT(0, deser_balance_info(json_info_200, res));
  TEST_ASSERT_EQUAL_INT(1000, res->maxResults);
  TEST_ASSERT_EQUAL_INT(25, res->count);
  TEST_ASSERT_EQUAL_INT(1338263, res->balance);

  free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_balance_info);
  RUN_TEST(test_get_balance);

  return UNITY_END();
}
