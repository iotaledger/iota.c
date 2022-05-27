// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/output_basic.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_basic_output_basic() {
  char const *const json_res =
      "{\"type\":3,\"amount\":\"1000000\",\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":"
      "16,\"nftId\":\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_basic_t *basic_output = NULL;
  int result = json_output_basic_deserialize(json_obj, &basic_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, basic_output->amount);
  TEST_ASSERT_NULL(basic_output->native_tokens);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(basic_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(1, condition_list_len(basic_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(basic_output->unlock_conditions, UNLOCK_COND_ADDRESS));

  TEST_ASSERT_NULL(basic_output->features);

  cJSON_Delete(json_obj);
  output_basic_free(basic_output);
}

void test_parse_basic_output_full() {
  char const *const json_res =
      "{\"type\":3,\"amount\":\"1000000\",\"nativeTokens\":[{\"id\":"
      "\"0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"0x93847598347598347598347598\"},{\"id\":"
      "\"0x09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"0x7598347598347598\"}],\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":16,\"nftId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}},{\"type\":1,\"returnAddress\":{"
      "\"type\":0,\"pubKeyHash\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"amount\":"
      "\"123456\"},{\"type\":2,\"milestoneIndex\":45598,\"unixTime\":123123},{\"type\":3,\"returnAddress\":{\"type\":0,"
      "\"pubKeyHash\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"milestoneIndex\":45598,"
      "\"unixTime\":123123}],\"features\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"0x6d657461646174615f6d657461646174615f6d657461646174615f6d657461646174615f\"},{\"type\":3,\"tag\":"
      "\"0x7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_basic_t *basic_output = NULL;
  int result = json_output_basic_deserialize(json_obj, &basic_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, basic_output->amount);

  // check native tokens
  TEST_ASSERT_NOT_NULL(basic_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT16(2, native_tokens_count(basic_output->native_tokens));
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(basic_output->native_tokens, token_id));
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(basic_output->native_tokens, token_id));

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(basic_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, condition_list_len(basic_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(basic_output->unlock_conditions, UNLOCK_COND_ADDRESS));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(basic_output->unlock_conditions, UNLOCK_COND_STORAGE));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(basic_output->unlock_conditions, UNLOCK_COND_TIMELOCK));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(basic_output->unlock_conditions, UNLOCK_COND_EXPIRATION));

  // check features
  TEST_ASSERT_NOT_NULL(basic_output->features);
  TEST_ASSERT_EQUAL_UINT8(3, feature_list_len(basic_output->features));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(basic_output->features, FEAT_SENDER_TYPE));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(basic_output->features, FEAT_METADATA_TYPE));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(basic_output->features, FEAT_TAG_TYPE));

  // print basic output
  output_basic_print(basic_output, 0);

  cJSON_Delete(json_obj);
  output_basic_free(basic_output);
}

void test_parse_basic_output_wrong_unlock_condition() {
  char const *const json_res =
      "{\"type\":3,\"amount\":\"1000000\",\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":"
      "16,\"nftId\":\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\"}}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_basic_t *basic_output = NULL;
  int result = json_output_basic_deserialize(json_obj, &basic_output);
  TEST_ASSERT_EQUAL_INT(0, result);
  // syntactic validation
  TEST_ASSERT_FALSE(output_basic_syntactic(basic_output));

  cJSON_Delete(json_obj);
  output_basic_free(basic_output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_basic_output_basic);
  RUN_TEST(test_parse_basic_output_full);
  RUN_TEST(test_parse_basic_output_wrong_unlock_condition);

  return UNITY_END();
}
