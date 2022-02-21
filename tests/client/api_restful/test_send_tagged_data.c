// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/restful/get_message.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "crypto/iota_crypto.h"
#include "test_config.h"

void setUp(void) {}

void tearDown(void) {}

char const* const tag = "IOTA TAGGED DATA";
char const* const tag_invalid_len = "IOTA TAGGED DATA, IOTA TAGGED DATA, IOTA TAGGED DATA, IOTA TAGGED DATA";
#define TAG_DATA_LEN 64

void test_send_tagged_data() {
  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};
  res_send_message_t res = {};
  res_send_message_print(&res, 0);
  res.is_error = false;
  // Check for NULL parameters
  TEST_ASSERT_EQUAL_INT(-1, send_tagged_data_message(NULL, tag, tag_data, TAG_DATA_LEN, &res));
  TEST_ASSERT_EQUAL_INT(-1, send_tagged_data_message(&ctx, tag, tag_data, TAG_DATA_LEN, NULL));
  TEST_ASSERT_EQUAL_INT(0, send_tagged_data_message(&ctx, "", tag_data, TAG_DATA_LEN, &res));
  TEST_ASSERT(res.is_error == true);
  res_send_message_print(&res, 0);
  res_err_free(res.u.error);
  res.is_error = false;

  TEST_ASSERT_EQUAL_INT(0, send_tagged_data_message(&ctx, tag, NULL, 0, &res));
  TEST_ASSERT(res.is_error == false);

  // Check for NULL tag data but tag_data_len > 0
  TEST_ASSERT_EQUAL_INT(-1, send_tagged_data_message(&ctx, tag, NULL, 10, &res));

  // Check for tag with len greater than MAX_TAG_LEN
  TEST_ASSERT_EQUAL_INT(-1, send_tagged_data_message(&ctx, tag_invalid_len, tag_data, TAG_DATA_LEN, &res));

  // Check for response
  TEST_ASSERT_EQUAL_INT(0, send_tagged_data_message(&ctx, tag, tag_data, TAG_DATA_LEN, &res));
  res_send_message_print(&res, 0);

  // Get message by message id
  res_message_t* msg_res = res_message_new();
  TEST_ASSERT_NOT_NULL(msg_res);
  TEST_ASSERT_EQUAL_INT(0, get_message_by_id(&ctx, res.u.msg_id, msg_res));

  // Get tagged data payload from message response
  tagged_data_t* tagged_data = (tagged_data_t*)msg_res->u.msg->payload;

  // Check if tag in the tagged data payload matches
  size_t tag_hex_len = BIN_TO_HEX_STR_BYTES(strlen(tag));
  byte_t tag_hex[TAGGED_DATA_TAG_MAX_LENGTH_BYTES] = {0};
  TEST_ASSERT(string2hex(tag, tag_hex, tag_hex_len) == 0);
  byte_buf_t* tag_buf = byte_buf_new_with_data(tag_hex, tag_hex_len);
  TEST_ASSERT_EQUAL_MEMORY(tagged_data->tag->data, tag_buf->data, tag_buf->len);
  byte_buf_free(tag_buf);

  // Check if data in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data->data->data, tag_data, TAG_DATA_LEN);
  res_message_free(msg_res);
}

int main() {
  UNITY_BEGIN();
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_send_tagged_data);
#endif
  return UNITY_END();
}
