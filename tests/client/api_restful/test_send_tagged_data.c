// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/restful/send_tagged_data.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "crypto/iota_crypto.h"
#include "test_config.h"

void setUp(void) {}

void tearDown(void) {}

#define TAG_LEN 14
#define TAG_INVALID_LEN 70
#define TAG_DATA_LEN 64

char const* const tag = "IOTA TAGGED DATA";
char const* const tag_invalid_len = "IOTA TAGGED DATA, IOTA TAGGED DATA, IOTA TAGGED DATA, IOTA TAGGED DATA";

void test_send_tagged_data() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);

  res_send_message_t res = {};
  res.is_error = false;

  TEST_ASSERT(send_tagged_data_message(&ctx, (byte_t*)tag, TAG_LEN, tag_data, TAG_DATA_LEN, &res) == 0);
}

int main() {
  UNITY_BEGIN();
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_send_tagged_data);
#endif
  return UNITY_END();
}
