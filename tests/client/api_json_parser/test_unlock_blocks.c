// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/unlock_blocks.h"
#include "client/constants.h"
#include "core/models/unlock_block.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_empty_unlocks() {
  char const *const json_res = "{\"unlockBlocks\":[]}";

  // deserialization
  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch unlock array
  cJSON *unlock_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_UNLOCKS);
  TEST_ASSERT_TRUE(cJSON_IsArray(unlock_data));

  unlock_list_t *unlock_list = unlock_list_new();
  int result = json_unlocks_deserialize(unlock_data, &unlock_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  cJSON_Delete(json_obj);

  // serialization
  cJSON *json_unlocks = cJSON_CreateObject();
  TEST_ASSERT_NOT_NULL(json_unlocks);
  cJSON *unlock_items = json_unlocks_serialize(unlock_list);
  TEST_ASSERT_NOT_NULL(unlock_items);
  // add array items to unlock object
  TEST_ASSERT_TRUE(cJSON_AddItemToObject(json_unlocks, JSON_KEY_UNLOCKS, unlock_items));
  // validate json string
  char *json_str = cJSON_PrintUnformatted(json_unlocks);
  TEST_ASSERT_EQUAL_STRING(json_res, json_str);
  // clean up
  free(json_str);
  cJSON_Delete(json_unlocks);

  unlock_list_free(unlock_list);
}

void test_parse_simple_unlocks() {
  char const *const json_res =
      "{\"unlockBlocks\":[{\"type\":0,\"signature\":{\"type\":0,\"publicKey\":"
      "\"0x31f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb\",\"signature\":"
      "\"0x1b51aab768dd145de99fc3710c7b05963803f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f81"
      "0ad0cc4b0210adaafd0a\"}},{\"type\":1,\"reference\":0}]}";
  // hex string of signature type + public key + signature
  char const *const sig_block_str =
      "0031f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb1b51aab768dd145de99fc3710c7b05963803f28c0a93"
      "532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f810ad0cc4b0210adaafd0a";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch unlock array
  cJSON *unlock_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_UNLOCKS);
  TEST_ASSERT_TRUE(cJSON_IsArray(unlock_data));

  unlock_list_t *unlock_list = unlock_list_new();
  int result = json_unlocks_deserialize(unlock_data, &unlock_list);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));

  // validate signature unlock
  unlock_t *b = unlock_list_get(unlock_list, 0);
  TEST_ASSERT_NOT_NULL(b);
  // check unlock type
  TEST_ASSERT(b->type == UNLOCK_SIGNATURE_TYPE);
  // check signature
  byte_t exp_sig_block[ED25519_SIGNATURE_BLOCK_BYTES];
  TEST_ASSERT(hex_2_bin(sig_block_str, strlen(sig_block_str), NULL, exp_sig_block, sizeof(exp_sig_block)) == 0);
  // dump_hex_str(b->unlock_data, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(exp_sig_block, b->obj, ED25519_SIGNATURE_BLOCK_BYTES);

  // validate reference unlock
  b = unlock_list_get(unlock_list, 1);
  TEST_ASSERT_NOT_NULL(b);
  // check unlock type
  TEST_ASSERT(b->type == UNLOCK_REFERENCE_TYPE);
  // check reference index
  TEST_ASSERT(0 == *((uint16_t *)b->obj));

  cJSON_Delete(json_obj);

  // serialization
  cJSON *json_unlocks = cJSON_CreateObject();
  TEST_ASSERT_NOT_NULL(json_unlocks);
  cJSON *unlock_items = json_unlocks_serialize(unlock_list);
  TEST_ASSERT_NOT_NULL(unlock_items);
  // add array items to unlock object
  TEST_ASSERT_TRUE(cJSON_AddItemToObject(json_unlocks, JSON_KEY_UNLOCKS, unlock_items));
  // validate json string
  char *json_str = cJSON_PrintUnformatted(json_unlocks);
  TEST_ASSERT_EQUAL_STRING(json_res, json_str);
  // clean up
  free(json_str);
  cJSON_Delete(json_unlocks);

  unlock_list_free(unlock_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_empty_unlocks);
  RUN_TEST(test_parse_simple_unlocks);

  return UNITY_END();
}
