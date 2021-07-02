// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/v1/get_balance.h"
#include "core/utils/byte_buffer.h"

char const* const addr_hex = "7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006";
char const* const addr_hex_invalid = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

void setUp(void) {}

void tearDown(void) {}

void test_get_balance() {
  iota_client_conf_t conf = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_balance_t* res = res_balance_new();
  TEST_ASSERT_NOT_NULL(res);

  // test null cases
  TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, NULL, res));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, res));

  // test invalid address
  TEST_ASSERT_EQUAL_INT(0, get_balance(&conf, addr_hex_invalid, res));
  TEST_ASSERT(res->is_error);
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  }

  // reset res
  res_balance_free(res);
  res = NULL;
  res = res_balance_new();
  TEST_ASSERT_NOT_NULL(res);

  // test for success
  TEST_ASSERT_EQUAL_INT(0, get_balance(&conf, addr_hex, res));
  if (res->is_error == true) {
    printf("Error: %s\n", res->u.error->msg);
  } else {
    // validate address type
    TEST_ASSERT(ADDRESS_VER_ED25519 == res->u.output_balance->address_type);
    // validate address data
    TEST_ASSERT_EQUAL_MEMORY(addr_hex, res->u.output_balance->address, IOTA_ADDRESS_HEX_BYTES);
  }

  res_balance_free(res);
}

void test_deser_balance_info() {
  char const* json_info_200 =
      "{\"data\":{\"addressType\":1,\"address\":\"7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006\","
      "\"balance\":1338263}}";
  char const* json_info_400 =
      "{\"error\":{\"code\":\"400\",\"message\":\"bad request, error: invalid address: "
      "iot1qxknyfvz2hnulyn6fqelg4ljyzm3sl8ewh5z4mhzuglu4eg9d26lg0h78ec, error: encoding\\/hex: invalid byte: U+0069 "
      "'i': invalid parameter\"}}";

  // test http status code 200
  res_balance_t* res = res_balance_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT_EQUAL_INT(0, deser_balance_info(json_info_200, res));
  TEST_ASSERT(1 == res->u.output_balance->address_type);
  TEST_ASSERT_EQUAL_STRING(addr_hex, res->u.output_balance->address);
  TEST_ASSERT_EQUAL_STRING(res->u.output_balance->address, addr_hex);
  TEST_ASSERT(1338263 == res->u.output_balance->balance);

  // clean up
  res_balance_free(res);
  res = NULL;

  // test http status code 400
  res = res_balance_new();
  TEST_ASSERT_NOT_NULL(res);

  TEST_ASSERT_EQUAL_INT(0, deser_balance_info(json_info_400, res));
  TEST_ASSERT(res->is_error == true);
  TEST_ASSERT_EQUAL_STRING("400", res->u.error->code);
  TEST_ASSERT_EQUAL_STRING(
      "bad request, error: invalid address: iot1qxknyfvz2hnulyn6fqelg4ljyzm3sl8ewh5z4mhzuglu4eg9d26lg0h78ec, error: "
      "encoding/hex: invalid byte: U+0069 'i': invalid parameter",
      res->u.error->msg);

  // clean up
  res_balance_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_balance_info);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_balance);
#endif
  return UNITY_END();
}
