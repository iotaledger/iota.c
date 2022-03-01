// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/output_alias.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/outputs.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_alias_output_basic() {
  char const *const json_res =
      "{\"type\":4, \"amount\":1000000,\"nativeTokens\":[],\"aliasId\":\"testAliasID\","
      "\"stateIndex\":12345,\"stateMetadata\":\"testMetadataTestMetadataTestMetadata\",\"foundryCounter\":54321,"
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}, "
      "{\"type\":5,\"address\":{\"type\":16,\"nftId\":\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}], "
      "\"featureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_alias_t *alias_output = NULL;
  int result = json_output_alias_deserialize(json_obj, &alias_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, alias_output->amount);
  TEST_ASSERT_NULL(alias_output->native_tokens);
  TEST_ASSERT_EQUAL_MEMORY("testAliasID", alias_output->alias_id, sizeof("testAliasID"));
  TEST_ASSERT_EQUAL_UINT32(12345, alias_output->state_index);
  TEST_ASSERT_EQUAL_UINT32(37, alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("testMetadataTestMetadataTestMetadata", alias_output->state_metadata->data,
                           alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_UINT32(54321, alias_output->foundry_counter);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(alias_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(alias_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_STATE));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_GOVERNOR));

  TEST_ASSERT_NULL(alias_output->feature_blocks);

  cJSON_Delete(json_obj);
  output_alias_free(alias_output);
}

void test_parse_alias_output_full() {
  char const *const json_res =
      "{\"type\":4,\"amount\":1000000,\"nativeTokens\":[{\"id\":"
      "\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"7598347598347598\"}],\"aliasId\":\"testAliasID\","
      "\"stateIndex\":12345,\"stateMetadata\":\"testMetadataTestMetadataTestMetadata\",\"foundryCounter\":54321,"
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}, "
      "{\"type\":5,\"address\":{\"type\":16,\"nftId\":\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}], "
      "\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":1,\"address\":{\"type\":0,"
      "\"pubKeyHash\":\"2258255e7cf927a4833f457433f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,"
      "\"data\":\"89dfjg0s9djfgdsfgjsdfg98sjdf98g23id0gjf0sdffgj098sdgcvb0xcuubx9b\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_alias_t *alias_output = NULL;
  int result = json_output_alias_deserialize(json_obj, &alias_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, alias_output->amount);

  // check native tokens
  TEST_ASSERT_NOT_NULL(alias_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT16(2, native_tokens_count(&alias_output->native_tokens));
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000", NATIVE_TOKEN_ID_HEX_BYTES,
            token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(&alias_output->native_tokens, token_id));
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000", NATIVE_TOKEN_ID_HEX_BYTES,
            token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(&alias_output->native_tokens, token_id));

  TEST_ASSERT_EQUAL_MEMORY("testAliasID", alias_output->alias_id, sizeof("testAliasID"));
  TEST_ASSERT_EQUAL_UINT32(12345, alias_output->state_index);
  TEST_ASSERT_EQUAL_UINT32(37, alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("testMetadataTestMetadataTestMetadata", alias_output->state_metadata->data,
                           alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_UINT32(54321, alias_output->foundry_counter);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(alias_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(alias_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_STATE));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_GOVERNOR));

  // check feature blocks
  TEST_ASSERT_NOT_NULL(alias_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(alias_output->feature_blocks));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(alias_output->feature_blocks, FEAT_SENDER_BLOCK));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(alias_output->feature_blocks, FEAT_ISSUER_BLOCK));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(alias_output->feature_blocks, FEAT_METADATA_BLOCK));

  // print alias output
  output_alias_print(alias_output, 0);

  cJSON_Delete(json_obj);
  output_alias_free(alias_output);
}

void test_parse_alias_output_wrong_unlock_condition() {
  char const *const json_res =
      "{\"type\":4, \"amount\":1000000,\"nativeTokens\":[],\"aliasId\":\"testAliasID\","
      "\"stateIndex\":12345,\"stateMetadata\":\"testMetadataTestMetadataTestMetadata\",\"foundryCounter\":54321,"
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}, "
      "{\"type\":0,\"address\":{\"type\":16,\"nfdId\":\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}], "
      "\"featureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_alias_t *alias_output = NULL;
  int result = json_output_alias_deserialize(json_obj, &alias_output);
  TEST_ASSERT_EQUAL_INT(-1, result);

  cJSON_Delete(json_obj);
  output_alias_free(alias_output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_alias_output_basic);
  RUN_TEST(test_parse_alias_output_full);
  RUN_TEST(test_parse_alias_output_wrong_unlock_condition);

  return UNITY_END();
}
