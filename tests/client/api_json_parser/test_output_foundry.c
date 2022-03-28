// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/output_foundry.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_foundry_output_basic() {
  char const *const json_res =
      "{\"type\":5,\"amount\":\"1000000\",\"nativeTokens\":[],\"serialNumber\":123456,\"tokenTag\":\"0xTokenTAGDemo\","
      "\"circulatingSupply\":\"0x20000000000000000000000000000000000000000\",\"maximumSupply\":"
      "\"0x30000000000000000000000000000000000000000\",\"tokenScheme\":{\"type\":0},\"unlockConditions\":[{\"type\":0,"
      "\"address\":{"
      "\"type\":8,\"aliasId\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c\"}}],\"featureBlocks\":[],"
      "\"immutableFeatureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_foundry_t *foundry_output = NULL;
  int result = json_output_foundry_deserialize(json_obj, &foundry_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, foundry_output->amount);
  TEST_ASSERT_NULL(foundry_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(123456, foundry_output->serial);
  TEST_ASSERT_EQUAL_MEMORY("TokenTAGDemo", foundry_output->token_tag, sizeof("TokenTAGDemo"));
  uint256_t *circ_cupply = uint256_from_str("20000000000000000000000000000000000000000");
  TEST_ASSERT_EQUAL_INT(0, uint256_equal(circ_cupply, &foundry_output->circ_supply));
  free(circ_cupply);
  uint256_t *max_cupply = uint256_from_str("30000000000000000000000000000000000000000");
  TEST_ASSERT_EQUAL_INT(0, uint256_equal(max_cupply, &foundry_output->max_supply));
  free(max_cupply);
  TEST_ASSERT_EQUAL_UINT8(0, foundry_output->token_scheme);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(foundry_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(1, cond_blk_list_len(foundry_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(foundry_output->unlock_conditions, UNLOCK_COND_IMMUT_ALIAS));

  TEST_ASSERT_NULL(foundry_output->feature_blocks);
  TEST_ASSERT_NULL(foundry_output->immutable_blocks);

  cJSON_Delete(json_obj);
  output_foundry_free(foundry_output);
}

void test_parse_foundry_output_full() {
  char const *const json_res =
      "{\"type\":5,\"amount\":\"1000000\",\"nativeTokens\":[{\"id\":"
      "\"0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\",\"amount\":"
      "\"0x93847598347598347598347598\"},{\"id\":"
      "\"0x09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"0x7598347598347598\"}],\"serialNumber\":123456,\"tokenTag\":\"0xTokenTAGDemo\","
      "\"circulatingSupply\":\"0x20000000000000000000000000000000000000000\",\"maximumSupply\":"
      "\"0x30000000000000000000000000000000000000000\",\"tokenScheme\":{\"type\":0},\"unlockConditions\":[{\"type\":0,"
      "\"address\":{\"type\":8,\"aliasId\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c\"}}],\"featureBlocks\":[{"
      "\"type\":2,\"data\":\"0x6d657461646174615f6d657461646174615f6d657461646174615f6d657461646174615f\"}],"
      "\"immutableFeatureBlocks\":[{\"type\":2,\"data\":"
      "\"0x696d6d757461626c654d65746164617461546573745f696d6d757461626c654d65746164617461546573745f\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_foundry_t *foundry_output = NULL;
  int result = json_output_foundry_deserialize(json_obj, &foundry_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, foundry_output->amount);

  // check native tokens
  TEST_ASSERT_NOT_NULL(foundry_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT16(2, native_tokens_count(foundry_output->native_tokens));
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(foundry_output->native_tokens, token_id));
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(foundry_output->native_tokens, token_id));

  TEST_ASSERT_EQUAL_UINT32(123456, foundry_output->serial);
  TEST_ASSERT_EQUAL_MEMORY("TokenTAGDemo", foundry_output->token_tag, sizeof("TokenTAGDemo"));
  uint256_t *circ_cupply = uint256_from_str("20000000000000000000000000000000000000000");
  TEST_ASSERT_EQUAL_INT(0, uint256_equal(circ_cupply, &foundry_output->circ_supply));
  free(circ_cupply);
  uint256_t *max_cupply = uint256_from_str("30000000000000000000000000000000000000000");
  TEST_ASSERT_EQUAL_INT(0, uint256_equal(max_cupply, &foundry_output->max_supply));
  free(max_cupply);
  TEST_ASSERT_EQUAL_UINT8(0, foundry_output->token_scheme);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(foundry_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(1, cond_blk_list_len(foundry_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(foundry_output->unlock_conditions, UNLOCK_COND_IMMUT_ALIAS));

  // check feature blocks
  TEST_ASSERT_NOT_NULL(foundry_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(foundry_output->feature_blocks));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(foundry_output->feature_blocks, FEAT_METADATA_BLOCK));

  // check immutable feature blocks
  TEST_ASSERT_NOT_NULL(foundry_output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(foundry_output->immutable_blocks));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(foundry_output->immutable_blocks, FEAT_METADATA_BLOCK));

  // print foundry output
  output_foundry_print(foundry_output, 0);

  cJSON_Delete(json_obj);
  output_foundry_free(foundry_output);
}

void test_parse_foundry_output_wrong_unlock_condition() {
  char const *const json_res =
      "{\"type\":5,\"amount\":\"1000000\",\"nativeTokens\":[{\"id\":"
      "\"0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\",\"amount\":"
      "\"0x93847598347598347598347598\"},{\"id\":"
      "\"0x09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"0x7598347598347598\"}],\"serialNumber\":123456,\"tokenTag\":\"0xTokenTAGDemo\","
      "\"circulatingSupply\":\"0x20000000000000000000000000000000000000000\",\"maximumSupply\":"
      "\"0x30000000000000000000000000000000000000000\",\"tokenScheme\":{\"type\":0},\"unlockConditions\":[{\"type\":4,"
      "\"address\":{\"type\":8,\"aliasId\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c\"}}],\"featureBlocks\":[{"
      "\"type\":2,\"data\":\"0xmetadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata\"}],"
      "\"immutableFeatureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_foundry_t *foundry_output = NULL;
  int result = json_output_foundry_deserialize(json_obj, &foundry_output);
  TEST_ASSERT_EQUAL_INT(-1, result);

  cJSON_Delete(json_obj);
  output_foundry_free(foundry_output);
}

void test_parse_foundry_output_wrong_feature_block() {
  char const *const json_res =
      "{\"type\":5,\"amount\":\"1000000\",\"nativeTokens\":[{\"id\":"
      "\"0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\",\"amount\":"
      "\"0x93847598347598347598347598\"},{\"id\":"
      "\"0x09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"70x598347598347598\"}],\"serialNumber\":123456,\"tokenTag\":\"0xTokenTAGDemo\","
      "\"circulatingSupply\":\"0x20000000000000000000000000000000000000000\",\"maximumSupply\":"
      "\"0x30000000000000000000000000000000000000000\",\"tokenScheme\":{\"type\":0},\"unlockConditions\":[{\"type\":0,"
      "\"address\":{"
      "\"type\":8,\"aliasId\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c\"}}],\"featureBlocks\":[{\"type\":3,\"tag\":"
      "\"0xtagDemo_tagDemo_tagDemo\"}],\"immutableFeatureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_foundry_t *foundry_output = NULL;
  int result = json_output_foundry_deserialize(json_obj, &foundry_output);
  TEST_ASSERT_EQUAL_INT(-1, result);

  cJSON_Delete(json_obj);
  output_foundry_free(foundry_output);
}

void test_parse_foundry_output_wrong_immutable_feature_block() {
  char const *const json_res =
      "{\"type\":5,\"amount\":\"1000000\",\"nativeTokens\":[{\"id\":"
      "\"0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\",\"amount\":"
      "\"0x93847598347598347598347598\"},{\"id\":"
      "\"0x09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"0x7598347598347598\"}],\"serialNumber\":123456,\"tokenTag\":\"0xTokenTAGDemo\","
      "\"circulatingSupply\":\"0x20000000000000000000000000000000000000000\",\"maximumSupply\":"
      "\"0x30000000000000000000000000000000000000000\",\"tokenScheme\":{\"type\":0},\"unlockConditions\":[{\"type\":0,"
      "\"address\":{"
      "\"type\":8,\"address\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c\"}}],\"featureBlocks\":[],"
      "\"immutableFeatureBlocks\":[{\"type\":3,\"tag\":\"0xtagDemo_tagDemo_tagDemo\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_foundry_t *foundry_output = NULL;
  int result = json_output_foundry_deserialize(json_obj, &foundry_output);
  TEST_ASSERT_EQUAL_INT(-1, result);

  cJSON_Delete(json_obj);
  output_foundry_free(foundry_output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_foundry_output_basic);
  RUN_TEST(test_parse_foundry_output_full);
  RUN_TEST(test_parse_foundry_output_wrong_unlock_condition);
  RUN_TEST(test_parse_foundry_output_wrong_feature_block);
  RUN_TEST(test_parse_foundry_output_wrong_immutable_feature_block);

  return UNITY_END();
}
