// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/output_nft.h"
#include "core/models/outputs/output_nft.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_nft_output_basic() {
  char const *const json_res =
      "{\"type\":6,\"amount\":\"1000000\",\"nativeTokens\":[],\"nftId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\","
      "\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":16,\"nftId\":"
      "\"0x6dadd4deda97ab502c441e46aa60cfd3d13cbcc902c441e402c441e402c441e4\"}}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_nft_t *nft_output = NULL;
  int result = json_output_nft_deserialize(json_obj, &nft_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, nft_output->amount);
  TEST_ASSERT_NULL(nft_output->native_tokens);

  // check NFT ID
  byte_t nft_id_test[NFT_ID_BYTES];
  hex_2_bin("19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f", BIN_TO_HEX_BYTES(NFT_ID_BYTES), NULL,
            nft_id_test, NFT_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(nft_id_test, nft_output->nft_id, NFT_ID_BYTES);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(nft_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(1, condition_list_len(nft_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_ADDRESS));

  TEST_ASSERT_NULL(nft_output->features);

  cJSON_Delete(json_obj);
  output_nft_free(nft_output);
}

void test_parse_nft_output_full() {
  char const *const json_res =
      "{\"type\":6,\"amount\":\"1000000\",\"nativeTokens\":[{\"id\":"
      "\"0x08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"0x93847598347598347598347598\"},{\"id\":"
      "\"0x09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"0x7598347598347598\"}],\"nftId\":\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\","
      "\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":16,\"nftId\":"
      "\"0x6dadd4deda97ab502c441e46aa60cfd3d13cbcc902c441e402c441e402c441e4\"}},{\"type\":1,\"returnAddress\":{"
      "\"type\":0,\"pubKeyHash\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"amount\":"
      "\"123456\"},{\"type\":2,\"milestoneIndex\":45598,\"unixTime\":123123},{\"type\":3,\"returnAddress\":{\"type\":0,"
      "\"pubKeyHash\":\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"milestoneIndex\":45598,"
      "\"unixTime\":123123}],\"features\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"0x6d657461646174615f6d657461646174615f6d657461646174615f6d657461646174615f\"},{\"type\":3,\"tag\":"
      "\"0x7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f\"}],"
      "\"immutableFeatures\":[{\"type\":1,\"address\":{\"type\":0,"
      "\"pubKeyHash\":\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"0x696d6d757461626c654d65746164617461546573745f696d6d757461626c654d65746164617461546573745f\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_nft_t *nft_output = NULL;
  int result = json_output_nft_deserialize(json_obj, &nft_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, nft_output->amount);

  // check native tokens
  TEST_ASSERT_NOT_NULL(nft_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT16(2, native_tokens_count(nft_output->native_tokens));
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(nft_output->native_tokens, token_id));
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), NULL, token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(nft_output->native_tokens, token_id));

  // check NFT ID
  byte_t nft_id_test[NFT_ID_BYTES];
  hex_2_bin("19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f", BIN_TO_HEX_BYTES(NFT_ID_BYTES), NULL,
            nft_id_test, NFT_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(nft_id_test, nft_output->nft_id, NFT_ID_BYTES);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(nft_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, condition_list_len(nft_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_ADDRESS));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_STORAGE));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_TIMELOCK));
  TEST_ASSERT_NOT_NULL(condition_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_EXPIRATION));

  // check features
  TEST_ASSERT_NOT_NULL(nft_output->features);
  TEST_ASSERT_EQUAL_UINT8(3, feature_list_len(nft_output->features));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(nft_output->features, FEAT_SENDER_TYPE));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(nft_output->features, FEAT_METADATA_TYPE));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(nft_output->features, FEAT_TAG_TYPE));

  // check immutable features
  TEST_ASSERT_NOT_NULL(nft_output->immutable_features);
  TEST_ASSERT_EQUAL_UINT8(2, feature_list_len(nft_output->immutable_features));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(nft_output->immutable_features, FEAT_ISSUER_TYPE));
  TEST_ASSERT_NOT_NULL(feature_list_get_type(nft_output->immutable_features, FEAT_METADATA_TYPE));

  // print NFT output
  output_nft_print(nft_output, 0);

  cJSON_Delete(json_obj);
  output_nft_free(nft_output);
}

void test_parse_nft_output_wrong_unlock_condition() {
  char const *const json_res =
      "{\"type\":6,\"amount\":\"1000000\",\"nativeTokens\":[],\"nftId\":"
      "\"0x19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f\","
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"nftId\":"
      "\"0x6dadd4deda97ab502c441e46aa60cfd3d13cbcc902c441e402c441e402c441e4\"}}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_nft_t *nft_output = NULL;
  int result = json_output_nft_deserialize(json_obj, &nft_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  // syntactic validation
  TEST_ASSERT_FALSE(output_nft_syntactic(nft_output));

  cJSON_Delete(json_obj);
  output_nft_free(nft_output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_nft_output_basic);
  RUN_TEST(test_parse_nft_output_full);
  RUN_TEST(test_parse_nft_output_wrong_unlock_condition);

  return UNITY_END();
}
