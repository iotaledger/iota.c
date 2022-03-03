// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/output_nft.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/outputs.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_nft_output_basic() {
  char const *const json_res =
      "{\"type\":6,\"amount\":1000000,\"nativeTokens\":[],\"nftId\":\"bebc45994f6bd9394f552b62c6e370ce1ab52d2e\","
      "\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}],\"featureBlocks\":[],\"immutableFeatureBlocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_nft_t *nft_output = NULL;
  int result = json_output_nft_deserialize(json_obj, &nft_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, nft_output->amount);
  TEST_ASSERT_NULL(nft_output->native_tokens);

  // check NFT ID
  byte_t nft_id_test[ADDRESS_NFT_BYTES];
  hex_2_bin("bebc45994f6bd9394f552b62c6e370ce1ab52d2e", ADDRESS_NFT_HEX_BYTES, nft_id_test, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(nft_id_test, nft_output->nft_id, ADDRESS_NFT_BYTES);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(nft_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(1, cond_blk_list_len(nft_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_ADDRESS));

  TEST_ASSERT_NULL(nft_output->feature_blocks);

  cJSON_Delete(json_obj);
  output_nft_free(nft_output);
}

void test_parse_nft_output_full() {
  char const *const json_res =
      "{\"type\":6,\"amount\":1000000,\"nativeTokens\":[{\"id\":"
      "\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"7598347598347598\"}],\"nftId\":\"bebc45994f6bd9394f552b62c6e370ce1ab52d2e\",\"unlockConditions\":[{\"type\":0,"
      "\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}},{\"type\":1,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"amount\":123456},{\"type\":2,"
      "\"milestoneIndex\":45598,\"unixTime\":123123},{\"type\":3,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"milestoneIndex\":45598,\"unixTime\":"
      "123123}],\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"metadataTest_metadataTest_metadataTest_metadataTest_metadataTest\"},{\"type\":3,\"tag\":\"tagTest_tagTest_"
      "tagTest_tagTest_tagTest_tagTest\"}],\"immutableFeatureBlocks\":[{\"type\":1,\"address\":{\"type\":0,"
      "\"pubKeyHash\":\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"immutableMetadataTest_immutableMetadataTest_immutableMetadataTest_ImmutableMetadataTest\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_nft_t *nft_output = NULL;
  int result = json_output_nft_deserialize(json_obj, &nft_output);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT64(1000000, nft_output->amount);

  // check native tokens
  TEST_ASSERT_NOT_NULL(nft_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT16(2, native_tokens_count(&nft_output->native_tokens));
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000", NATIVE_TOKEN_ID_HEX_BYTES,
            token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(&nft_output->native_tokens, token_id));
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000", NATIVE_TOKEN_ID_HEX_BYTES,
            token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_NOT_NULL(native_tokens_find_by_id(&nft_output->native_tokens, token_id));

  // check NFT ID
  byte_t nft_id_test[ADDRESS_NFT_BYTES];
  hex_2_bin("bebc45994f6bd9394f552b62c6e370ce1ab52d2e", ADDRESS_NFT_HEX_BYTES, nft_id_test, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(nft_id_test, nft_output->nft_id, ADDRESS_NFT_BYTES);

  // check unlock conditions
  TEST_ASSERT_NOT_NULL(nft_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(nft_output->unlock_conditions));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_ADDRESS));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_DUST));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_TIMELOCK));
  TEST_ASSERT_NOT_NULL(cond_blk_list_get_type(nft_output->unlock_conditions, UNLOCK_COND_EXPIRATION));

  // check feature blocks
  TEST_ASSERT_NOT_NULL(nft_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(nft_output->feature_blocks));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(nft_output->feature_blocks, FEAT_SENDER_BLOCK));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(nft_output->feature_blocks, FEAT_METADATA_BLOCK));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(nft_output->feature_blocks, FEAT_TAG_BLOCK));

  // check immutable feature blocks
  TEST_ASSERT_NOT_NULL(nft_output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(nft_output->immutable_blocks));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(nft_output->immutable_blocks, FEAT_ISSUER_BLOCK));
  TEST_ASSERT_NOT_NULL(feat_blk_list_get_type(nft_output->immutable_blocks, FEAT_METADATA_BLOCK));

  // print NFT output
  output_nft_print(nft_output, 0);

  cJSON_Delete(json_obj);
  output_nft_free(nft_output);
}

void test_parse_nft_output_wrong_unlock_condition() {
  char const *const json_res =
      "{\"type\":6,\"amount\":1000000,\"nativeTokens\":[],\"nftId\":\"bebc45994f6bd9394f552b62c6e370ce1ab52d2e\","
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}],\"featureBlocks\":[],\"immutableData\":\"metadataTest_"
      "metadataTest_metadataTest_metadataTest\"}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  output_nft_t *nft_output = NULL;
  int result = json_output_nft_deserialize(json_obj, &nft_output);
  TEST_ASSERT_EQUAL_INT(-1, result);

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
