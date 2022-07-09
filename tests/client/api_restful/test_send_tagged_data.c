// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_parser/json_keys.h"
#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/send_tagged_data.h"
#include "client/network/http.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"
#include "crypto/iota_crypto.h"
#include "test_config.h"
#include "unity/unity.h"

#define TAG_LEN 16
#define TAG_INVALID_LEN 70
#define TAG_DATA_LEN 64

char const* const tag = "IOTA TAGGED DATA";
char const* const tag_invalid_len = "IOTA TAGGED DATA, IOTA TAGGED DATA, IOTA TAGGED DATA, IOTA TAGGED DATA";
byte_t binary_tag[TAG_LEN] = {0x13, 0x94, 0x12, 0xdd, 0x2b, 0xff, 0xd4, 0x55, 0x62, 0x90, 0xfd, 0x6f, 0xa8, 0x30, 0x1f};

void setUp(void) {}

void tearDown(void) {}

void test_send_tagged_data() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);
  res_send_block_t res = {};
  res.is_error = false;

  // invalid parameters
  TEST_ASSERT(send_tagged_data_block(NULL, 2, (byte_t*)tag, TAG_LEN, tag_data, TAG_DATA_LEN, &res) == -1);
  TEST_ASSERT(send_tagged_data_block(&ctx, 2, NULL, TAG_LEN, tag_data, TAG_DATA_LEN, &res) == -1);
  TEST_ASSERT(send_tagged_data_block(&ctx, 2, (byte_t*)tag, TAG_LEN, tag_data, TAG_DATA_LEN, NULL) == -1);
  TEST_ASSERT(send_tagged_data_block(&ctx, 2, (byte_t*)tag, TAG_LEN, NULL, TAG_DATA_LEN, &res) == -1);
  TEST_ASSERT(send_tagged_data_block(&ctx, 2, (byte_t*)tag_invalid_len, TAG_INVALID_LEN, NULL, TAG_DATA_LEN, &res) ==
              -1);

  // Valid data and tag
  TEST_ASSERT(send_tagged_data_block(&ctx, 2, (byte_t*)tag, TAG_LEN, tag_data, TAG_DATA_LEN, &res) == 0);

  iota_str_t* cmd = NULL;
  char const* const cmd_str = "/blocks/0x";

  cmd = iota_str_reserve(strlen(CORE_API_ROUTE) + strlen(cmd_str) + BIN_TO_HEX_BYTES(IOTA_BLOCK_ID_BYTES) + 1);
  TEST_ASSERT_NOT_NULL(cmd);

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s", CORE_API_ROUTE, cmd_str, res.u.blk_id);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = ctx.host, .path = cmd->buf, .use_tls = ctx.use_tls, .port = ctx.port};

  byte_buf_t* http_res = byte_buf_new();
  TEST_ASSERT_NOT_NULL(http_res);

  // send request via http client
  long st = 0;
  TEST_ASSERT(http_client_get(&http_conf, http_res, &st) == 0);
  byte_buf2str(http_res);

  cJSON* json_obj = cJSON_Parse((char const* const)http_res->data);
  TEST_ASSERT_NOT_NULL(json_obj);
  cJSON* payload = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_PAYLOAD);
  TEST_ASSERT_NOT_NULL(payload);
  // tag
  cJSON* json_tag = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_TAG);
  TEST_ASSERT_NOT_NULL(json_tag);
  // data
  cJSON* json_data = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_DATA);
  TEST_ASSERT_NOT_NULL(json_data);

  char* tag_hex = malloc(JSON_STR_WITH_PREFIX_BYTES(strlen(tag)));
  TEST_ASSERT_NOT_NULL(tag_hex);
  TEST_ASSERT(bin_2_hex((byte_t*)tag, strlen(tag), NULL, tag_hex, JSON_STR_WITH_PREFIX_BYTES(strlen(tag))) == 0);

  // check if tag is matching
  TEST_ASSERT_EQUAL_MEMORY(tag_hex, json_tag->valuestring + JSON_HEX_ENCODED_STR_PREFIX_LEN, TAG_LEN);

  char data_hex[JSON_STR_WITH_PREFIX_BYTES(TAG_DATA_LEN)] = {0};
  TEST_ASSERT(bin_2_hex(tag_data, TAG_DATA_LEN, NULL, data_hex, sizeof(data_hex)) == 0);

  // check if data is matching
  TEST_ASSERT_EQUAL_MEMORY(data_hex, json_data->valuestring + JSON_HEX_ENCODED_STR_PREFIX_LEN, TAG_DATA_LEN);

  free(tag_hex);
  iota_str_destroy(cmd);
  cJSON_Delete(json_obj);
  byte_buf_free(http_res);
}

void test_send_binary_tagged_data() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);
  res_send_block_t res = {};
  res.is_error = false;

  // Valid data and tag
  TEST_ASSERT(send_tagged_data_block(&ctx, 2, binary_tag, TAG_LEN, tag_data, TAG_DATA_LEN, &res) == 0);

  iota_str_t* cmd = NULL;
  char const* const cmd_str = "/blocks/0x";

  cmd = iota_str_reserve(strlen(CORE_API_ROUTE) + strlen(cmd_str) + BIN_TO_HEX_BYTES(IOTA_BLOCK_ID_BYTES) + 1);
  TEST_ASSERT_NOT_NULL(cmd);

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s", CORE_API_ROUTE, cmd_str, res.u.blk_id);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = ctx.host, .path = cmd->buf, .use_tls = ctx.use_tls, .port = ctx.port};

  byte_buf_t* http_res = byte_buf_new();
  TEST_ASSERT_NOT_NULL(http_res);

  // send request via http client
  long st = 0;
  TEST_ASSERT(http_client_get(&http_conf, http_res, &st) == 0);
  byte_buf2str(http_res);

  cJSON* json_obj = cJSON_Parse((char const* const)http_res->data);
  TEST_ASSERT_NOT_NULL(json_obj);
  cJSON* payload = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_PAYLOAD);
  TEST_ASSERT_NOT_NULL(payload);
  // tag
  cJSON* json_tag = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_TAG);
  TEST_ASSERT_NOT_NULL(json_tag);
  // data
  cJSON* json_data = cJSON_GetObjectItemCaseSensitive(payload, JSON_KEY_DATA);
  TEST_ASSERT_NOT_NULL(json_data);

  char tag_hex[JSON_STR_WITH_PREFIX_BYTES(TAG_LEN)] = {0};
  TEST_ASSERT(bin_2_hex(binary_tag, TAG_LEN, JSON_HEX_ENCODED_STRING_PREFIX, tag_hex, sizeof(tag_hex)) == 0);

  // check if tag is matching
  TEST_ASSERT_EQUAL_MEMORY(tag_hex, json_tag->valuestring, TAG_LEN);

  char data_hex[JSON_STR_WITH_PREFIX_BYTES(TAG_DATA_LEN)] = {0};
  TEST_ASSERT(bin_2_hex(tag_data, TAG_DATA_LEN, JSON_HEX_ENCODED_STRING_PREFIX, data_hex, sizeof(data_hex)) == 0);

  // check if data is matching
  TEST_ASSERT_EQUAL_MEMORY(data_hex, json_data->valuestring, TAG_DATA_LEN);

  cJSON_Delete(json_obj);
  byte_buf_free(http_res);
  iota_str_destroy(cmd);
}

int main() {
  UNITY_BEGIN();
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_send_tagged_data);
  RUN_TEST(test_send_binary_tagged_data);
#endif
  return UNITY_END();
}
