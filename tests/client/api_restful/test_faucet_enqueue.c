// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>

#include "client/api/restful/faucet_enqueue.h"
#include "test_config.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_faucet_enqueue(void) {
  const char *const address_bech32 = "atoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5ymep8aa";
  const char *const address_bech32_invalid = "pqoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5ymep8ab";
  const char *const address_bech32_invalid_len = "atoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5";

  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_faucet_enqueue_t res = {};

  // Test NULL inputs
  TEST_ASSERT_EQUAL_INT(-1, req_tokens_to_addr_from_faucet(NULL, address_bech32, &res));
  TEST_ASSERT_EQUAL_INT(-1, req_tokens_to_addr_from_faucet(&ctx, NULL, &res));
  TEST_ASSERT_EQUAL_INT(-1, req_tokens_to_addr_from_faucet(&ctx, address_bech32, NULL));

  // Test bech32 address with invalid len
  TEST_ASSERT_EQUAL_INT(0, req_tokens_to_addr_from_faucet(&ctx, address_bech32_invalid_len, &res));
  TEST_ASSERT(res.is_error == true);
  res_err_free(res.u.error);

  // Test for invalid bech32 address
  res.is_error = false;
  TEST_ASSERT_EQUAL_INT(0, req_tokens_to_addr_from_faucet(&ctx, address_bech32_invalid, &res));
  TEST_ASSERT(res.is_error == true);
  res_err_free(res.u.error);

  // Test for valid bech32
  res.is_error = false;
  TEST_ASSERT_EQUAL_INT(0, req_tokens_to_addr_from_faucet(&ctx, address_bech32, &res));
  TEST_ASSERT(res.is_error == false);
  printf("Address : %s\n", res.u.req_res.bech32_address);
  printf("Waiting Requests : %d\n", res.u.req_res.waiting_reqs_count);
}

int main() {
  UNITY_BEGIN();
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_faucet_enqueue);
#endif
  return UNITY_END();
}
