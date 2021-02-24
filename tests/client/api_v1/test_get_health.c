// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/v1/get_health.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_health() {
  iota_client_conf_t ctx = {.url = TEST_NODE_ENDPOINT, .port = TEST_NODE_PORT};
  bool health = false;
  TEST_ASSERT(get_health(&ctx, &health) == 0);
}

int main() {
  UNITY_BEGIN();

#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_health);
#endif

  return UNITY_END();
}