// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/output_extended.h"
#include "core/models/outputs/output_extended.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_extended_output_basic() {
  char const *const json_res =
      "{\"type\":3,\"amount\":1000000,\"nativeTokens\":[],\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":16,"
      "\"address\":\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}],\"featureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  utxo_outputs_list_t *output_list = utxo_outputs_new();
  int result = json_output_extended_deserialize(json_obj, &output_list);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(1, utxo_outputs_count(output_list));
  utxo_output_t *output = utxo_outputs_get(output_list, 0);
  TEST_ASSERT_EQUAL_UINT8(OUTPUT_EXTENDED, output->output_type);

  output_extended_t *extended_output = (output_extended_t *)output->output;
  TEST_ASSERT_EQUAL_UINT64(1000000, extended_output->amount);
  TEST_ASSERT_NULL(extended_output->native_tokens);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(extended_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(1, cond_blk_list_len(extended_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(extended_output->unlock_conditions, UNLOCK_COND_ADDRESS));

  TEST_ASSERT_NULL(extended_output->feature_blocks);

  cJSON_Delete(json_obj);
  utxo_outputs_free(output_list);
}

void test_parse_extended_output_full() {
  char const *const json_res =
      "{\"type\":3,\"amount\":1000000,\"nativeTokens\":[{\"id\":"
      "\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"7598347598347598\"}],\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":16,\"address\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}},{\"type\":1,\"returnAddress\":{\"type\":0,\"address\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"amount\":123456},{\"type\":2,"
      "\"milestoneIndex\":45598,\"unixTime\":123123},{\"type\":3,\"returnAddress\":{\"type\":0,\"address\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"milestoneIndex\":45598,\"unixTime\":"
      "123123}],\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"address\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":\"metadataTest_"
      "metadataTest_metadataTest_metadataTest_metadataTest\"},{\"type\":3,\"tag\":\"tagTest_tagTest_tagTest_"
      "tagTest_tagTest_tagTest\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  utxo_outputs_list_t *output_list = utxo_outputs_new();
  int result = json_output_extended_deserialize(json_obj, &output_list);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(1, utxo_outputs_count(output_list));
  utxo_output_t *output = utxo_outputs_get(output_list, 0);
  TEST_ASSERT_EQUAL_UINT8(OUTPUT_EXTENDED, output->output_type);

  output_extended_t *extended_output = (output_extended_t *)output->output;
  TEST_ASSERT_EQUAL_UINT64(1000000, extended_output->amount);

  // check native tokens
  TEST_ASSERT_NOT_NULL(extended_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT16(2, native_tokens_count(&extended_output->native_tokens));
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000", NATIVE_TOKEN_ID_HEX_BYTES,
            token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(&extended_output->native_tokens, token_id));
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000", NATIVE_TOKEN_ID_HEX_BYTES,
            token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(&extended_output->native_tokens, token_id));

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(extended_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(extended_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(extended_output->unlock_conditions, UNLOCK_COND_ADDRESS));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(extended_output->unlock_conditions, UNLOCK_COND_DUST));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(extended_output->unlock_conditions, UNLOCK_COND_TIMELOCK));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(extended_output->unlock_conditions, UNLOCK_COND_EXPIRATION));

  // check feature blocks
  TEST_ASSERT_NOT_NULL(extended_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(extended_output->feature_blocks));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(extended_output->feature_blocks, FEAT_SENDER_BLOCK));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(extended_output->feature_blocks, FEAT_METADATA_BLOCK));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(extended_output->feature_blocks, FEAT_TAG_BLOCK));

  // print output list
  utxo_outputs_print(output_list, 0);

  cJSON_Delete(json_obj);
  utxo_outputs_free(output_list);
}

void test_parse_extended_output_wrong_unlock_condition() {
  char const *const json_res =
      "{\"type\":3,\"amount\":1000000,\"nativeTokens\":[],\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,"
      "\"address\":\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}],\"featureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  utxo_outputs_list_t *output_list = utxo_outputs_new();
  int result = json_output_extended_deserialize(json_obj, &output_list);
  TEST_ASSERT_EQUAL_INT(-1, result);

  cJSON_Delete(json_obj);
  utxo_outputs_free(output_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_extended_output_basic);
  RUN_TEST(test_parse_extended_output_full);
  RUN_TEST(test_parse_extended_output_wrong_unlock_condition);

  return UNITY_END();
}
