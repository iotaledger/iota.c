// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/unlock_blocks.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_blocks_empty() {
  char const *const json_res = "{\"unlockBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch unlock block array
  cJSON *block_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_UNLOCK_BLOCKS);
  TEST_ASSERT_TRUE(cJSON_IsArray(block_data));

  unlock_list_t *block_list = unlock_blocks_new();
  int result = json_unlock_blocks_deserialize(block_data, &block_list);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(block_list));

  cJSON_Delete(json_obj);
  unlock_blocks_free(block_list);
}

void test_parse_block_simple() {
  char const *const json_res =
      "{\"unlockBlocks\":[{\"type\":0,\"signature\":{\"type\":0,\"publicKey\":"
      "\"31f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb\",\"signature\":"
      "\"1b51aab768dd145de99fc3710c7b05963803f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f810a"
      "d0cc4b0210adaafd0a\"}}]}";
  // hex string of signature type + public key + signature
  char const *const sig_block_str =
      "0031f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb1b51aab768dd145de99fc3710c7b05963803f28c0a9353"
      "2341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f810ad0cc4b0210adaafd0a";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch unlock block array
  cJSON *block_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_UNLOCK_BLOCKS);
  TEST_ASSERT_TRUE(cJSON_IsArray(block_data));

  unlock_list_t *block_list = unlock_blocks_new();
  int result = json_unlock_blocks_deserialize(block_data, &block_list);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(block_list));

  unlock_block_t *b = unlock_blocks_get(block_list, 0);
  TEST_ASSERT_NOT_NULL(b);

  // validate block type
  TEST_ASSERT(b->type == UNLOCK_BLOCK_TYPE_SIGNATURE);

  // validate signature block
  byte_t exp_sig_block[ED25519_SIGNATURE_BLOCK_BYTES];
  TEST_ASSERT(hex_2_bin(sig_block_str, strlen(sig_block_str), exp_sig_block, sizeof(exp_sig_block)) == 0);
  // dump_hex_str(b->block_data, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(exp_sig_block, b->block_data, ED25519_SIGNATURE_BLOCK_BYTES);

  cJSON_Delete(json_obj);
  unlock_blocks_free(block_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_blocks_empty);
  RUN_TEST(test_parse_block_simple);

  return UNITY_END();
}
