// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/feat_blocks.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_feat_block_sender() {
  char const* const json_res =
      "{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feat_blk_list_t* blk_list = feat_blk_list_new();
  int result = json_feat_blk_sender_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feat_blk_list_len(blk_list));

  feat_block_t* feat_block = feat_blk_list_get_type(blk_list, FEAT_SENDER_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", ADDRESS_ED25519_HEX_BYTES,
            test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)feat_block->block)));

  cJSON_Delete(json_obj);
  feat_blk_list_free(blk_list);
}

void test_feat_block_issuer() {
  char const* const json_res =
      "{\"type\":1,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feat_blk_list_t* blk_list = feat_blk_list_new();
  int result = json_feat_blk_issuer_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feat_blk_list_len(blk_list));

  feat_block_t* feat_block = feat_blk_list_get_type(blk_list, FEAT_ISSUER_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, feat_block->type);
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", ADDRESS_ED25519_HEX_BYTES,
            test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)feat_block->block)));

  cJSON_Delete(json_obj);
  feat_blk_list_free(blk_list);
}

void test_feat_block_metadata() {
  char const* const json_res =
      "{\"type\":2,\"data\":\"metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata\"}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feat_blk_list_t* blk_list = feat_blk_list_new();
  int result = json_feat_blk_metadata_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feat_blk_list_len(blk_list));

  feat_block_t* feat_block = feat_blk_list_get_type(blk_list, FEAT_METADATA_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  feat_metadata_blk_t* metadata = (feat_metadata_blk_t*)feat_block->block;
  TEST_ASSERT_EQUAL_UINT32(80, metadata->data_len);
  TEST_ASSERT_EQUAL_MEMORY("metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata",
                           metadata->data, metadata->data_len);

  cJSON_Delete(json_obj);
  feat_blk_list_free(blk_list);
}

void test_feat_block_tag() {
  char const* const json_res =
      "{\"type\":3,\"tag\":\"tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_\"}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feat_blk_list_t* blk_list = feat_blk_list_new();
  int result = json_feat_blk_tag_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feat_blk_list_len(blk_list));

  feat_block_t* feat_block = feat_blk_list_get_type(blk_list, FEAT_TAG_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_BLOCK, feat_block->type);
  feat_tag_blk_t* tag = (feat_tag_blk_t*)feat_block->block;
  TEST_ASSERT_EQUAL_UINT32(64, tag->tag_len);
  TEST_ASSERT_EQUAL_MEMORY("tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_", tag->tag, tag->tag_len);

  cJSON_Delete(json_obj);
  feat_blk_list_free(blk_list);
}

void test_feat_blocks() {
  char const* const json_res =
      "{\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":1,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":2,\"data\":\"metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata\"},"
      "{\"type\":3,\"tag\":\"tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_\"}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feat_blk_list_t* blk_list = feat_blk_list_new();
  int result = json_feat_blocks_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(4, feat_blk_list_len(blk_list));
  feat_block_t* feat_block = feat_blk_list_get_type(blk_list, FEAT_SENDER_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);
  feat_block = feat_blk_list_get_type(blk_list, FEAT_ISSUER_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);
  feat_block = feat_blk_list_get_type(blk_list, FEAT_METADATA_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);
  feat_block = feat_blk_list_get_type(blk_list, FEAT_TAG_BLOCK);
  TEST_ASSERT_NOT_NULL(feat_block);

  // print feature blocks
  feat_blk_list_print(blk_list, 0);

  cJSON_Delete(json_obj);
  feat_blk_list_free(blk_list);
}

void test_feat_blocks_unsupported_type() {
  char const* const json_res =
      "{\"featureBlocks\":[{\"type\":4,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feat_blk_list_t* blk_list = feat_blk_list_new();
  int result = json_feat_blocks_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(-1, result);
  TEST_ASSERT_EQUAL_INT(0, feat_blk_list_len(blk_list));

  cJSON_Delete(json_obj);
  feat_blk_list_free(blk_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_feat_block_sender);
  RUN_TEST(test_feat_block_issuer);
  RUN_TEST(test_feat_block_metadata);
  RUN_TEST(test_feat_block_tag);
  RUN_TEST(test_feat_blocks);
  RUN_TEST(test_feat_blocks_unsupported_type);

  return UNITY_END();
}
