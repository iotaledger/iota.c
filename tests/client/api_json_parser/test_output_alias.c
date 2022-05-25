// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/output_alias.h"
#include "core/models/outputs/output_alias.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_alias_output_basic() {
  char const *const json_res =
      "{\"type\":4,\"amount\":\"1000000\",\"nativeTokens\":[],\"aliasId\":"
      "\"0xa2ea52db9c6185ef42e295dff8891c0d291c3fb7bbea8dadf1aaaa74adc6faad\",\"stateIndex\":12345,\"stateMetadata\":"
      "\"0xtestMetadataTestMetadataTestMetadata\",\"foundryCounter\":54321,\"unlockConditions\":[{\"type\":4,"
      "\"address\":{\"type\":16,\"nftId\":\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}, "
      "{\"type\":5,\"address\":{\"type\":16,\"nftId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}],\"featureBlocks\":[],"
      "\"immutableFeatureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_alias_t *alias_output = NULL;
  int result = json_output_alias_deserialize(json_obj, &alias_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, alias_output->amount);
  TEST_ASSERT_NULL(alias_output->native_tokens);
  byte_t alias_id[ALIAS_ID_BYTES];
  hex_2_bin("a2ea52db9c6185ef42e295dff8891c0d291c3fb7bbea8dadf1aaaa74adc6faad", BIN_TO_HEX_BYTES(ALIAS_ID_BYTES), NULL,
            alias_id, ALIAS_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(alias_id, alias_output->alias_id, sizeof(alias_output->alias_id));
  TEST_ASSERT_EQUAL_UINT32(12345, alias_output->state_index);
  TEST_ASSERT_EQUAL_UINT32(37, alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("testMetadataTestMetadataTestMetadata", alias_output->state_metadata->data,
                           alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_UINT32(54321, alias_output->foundry_counter);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(alias_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(alias_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_STATE));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_GOVERNOR));

  TEST_ASSERT_NULL(alias_output->features);

  cJSON_Delete(json_obj);
  output_alias_free(alias_output);
}

void test_parse_alias_output_full() {
  char const *const json_res =
      "{\"type\":4,\"amount\":\"1000000\",\"nativeTokens\":[{\"id\":"
      "\"0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"0x93847598347598347598347598\"},{\"id\":"
      "\"0x09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"0x7598347598347598\"}],\"aliasId\":\"0xa2ea52db9c6185ef42e295dff8891c0d291c3fb7bbea8dadf1aaaa74adc6faad\","
      "\"stateIndex\":12345,\"stateMetadata\":\"0xtestMetadataTestMetadataTestMetadata\",\"foundryCounter\":54321,"
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"nftId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}, "
      "{\"type\":5,\"address\":{\"type\":16,\"nftId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}], "
      "\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,"
      "\"data\":\"0x6d657461646174615f6d657461646174615f6d657461646174615f6d657461646174615f\"}],"
      "\"immutableFeatureBlocks\":[{\"type\":1,\"address\":{\"type\":0,"
      "\"pubKeyHash\":\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"0x696d6d757461626c654d65746164617461546573745f696d6d757461626c654d65746164617461546573745f\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_alias_t *alias_output = NULL;
  int result = json_output_alias_deserialize(json_obj, &alias_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, alias_output->amount);

  // check native tokens
  TEST_ASSERT_NOT_NULL(alias_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT16(2, native_tokens_count(alias_output->native_tokens));
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(alias_output->native_tokens, token_id));
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(alias_output->native_tokens, token_id));

  byte_t alias_id[ALIAS_ID_BYTES];
  hex_2_bin("a2ea52db9c6185ef42e295dff8891c0d291c3fb7bbea8dadf1aaaa74adc6faad", BIN_TO_HEX_BYTES(ALIAS_ID_BYTES), NULL,
            alias_id, ALIAS_ID_BYTES);
  TEST_ASSERT_EQUAL_UINT32(12345, alias_output->state_index);
  TEST_ASSERT_EQUAL_UINT32(37, alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("testMetadataTestMetadataTestMetadata", alias_output->state_metadata->data,
                           alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_UINT32(54321, alias_output->foundry_counter);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(alias_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(alias_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_STATE));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(alias_output->unlock_conditions, UNLOCK_COND_GOVERNOR));

  // check features
  TEST_ASSERT_NOT_NULL(alias_output->features);
  TEST_ASSERT_EQUAL_UINT8(2, feature_list_len(alias_output->features));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(alias_output->features, FEAT_SENDER_TYPE));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(alias_output->features, FEAT_METADATA_TYPE));

  // check immutable features
  TEST_ASSERT_NOT_NULL(alias_output->immutable_features);
  TEST_ASSERT_EQUAL_UINT8(2, feature_list_len(alias_output->immutable_features));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(alias_output->immutable_features, FEAT_ISSUER_TYPE));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(alias_output->immutable_features, FEAT_METADATA_TYPE));

  // print alias output
  output_alias_print(alias_output, 0);

  cJSON_Delete(json_obj);
  output_alias_free(alias_output);
}

void test_parse_alias_output_wrong_unlock_condition() {
  char const *const json_res =
      "{\"type\":4, \"amount\":\"1000000\",\"nativeTokens\":[],\"aliasId\":\"0xtestAliasID\","
      "\"stateIndex\":12345,\"stateMetadata\":\"0xtestMetadataTestMetadataTestMetadata\",\"foundryCounter\":54321,"
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"nftId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}, "
      "{\"type\":0,\"address\":{\"type\":16,\"nfdId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}], "
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
