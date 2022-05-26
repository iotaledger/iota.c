// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/features.h"
#include "client/constants.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_feature_sender() {
  char const* const json_res =
      "{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feature_list_t* feat_list = feature_list_new();
  int result = json_feat_sender_deserialize(json_obj, &feat_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feature_list_len(feat_list));

  output_feature_t* feat = feature_list_get_type(feat_list, FEAT_SENDER_TYPE);
  TEST_ASSERT_NOT_NULL(feat);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_TYPE, feat->type);
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)feat->obj)));

  cJSON_Delete(json_obj);
  feature_list_free(feat_list);
}

void test_feature_issuer() {
  char const* const json_res =
      "{\"type\":1,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feature_list_t* blk_list = feature_list_new();
  int result = json_feat_issuer_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feature_list_len(blk_list));

  output_feature_t* feat = feature_list_get_type(blk_list, FEAT_ISSUER_TYPE);
  TEST_ASSERT_NOT_NULL(feat);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_TYPE, feat->type);
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)feat->obj)));

  cJSON_Delete(json_obj);
  feature_list_free(blk_list);
}

void test_feature_metadata() {
  char const* const json_res =
      "{\"type\":2,\"data\":\"0x6d657461646174615f6d657461646174615f6d657461646174615f6d657461646174615f\"}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feature_list_t* blk_list = feature_list_new();
  int result = json_feat_metadata_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feature_list_len(blk_list));

  output_feature_t* feat = feature_list_get_type(blk_list, FEAT_METADATA_TYPE);
  TEST_ASSERT_NOT_NULL(feat);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_TYPE, feat->type);
  feature_metadata_t* metadata = (feature_metadata_t*)feat->obj;
  TEST_ASSERT_EQUAL_UINT32(36, metadata->data_len);
  TEST_ASSERT_EQUAL_MEMORY("metadata_metadata_metadata_metadata_", metadata->data, metadata->data_len);

  cJSON_Delete(json_obj);
  feature_list_free(blk_list);
}

void test_output_feature_tag() {
  char const* const json_res =
      "{\"type\":3,\"tag\":\"0x7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f\"}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feature_list_t* blk_list = feature_list_new();
  int result = json_feat_tag_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, feature_list_len(blk_list));

  output_feature_t* feat = feature_list_get_type(blk_list, FEAT_TAG_TYPE);
  TEST_ASSERT_NOT_NULL(feat);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_TYPE, feat->type);
  feature_tag_t* tag = (feature_tag_t*)feat->obj;
  TEST_ASSERT_EQUAL_UINT32(40, tag->tag_len);
  TEST_ASSERT_EQUAL_MEMORY("tag_tag_tag_tag_tag_tag_tag_tag_tag_tag_", tag->tag, tag->tag_len);

  cJSON_Delete(json_obj);
  feature_list_free(blk_list);
}

void test_features() {
  char const* const json_res =
      "{\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":1,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":2,\"data\":\"0x6d657461646174615f6d657461646174615f6d657461646174615f6d657461646174615f\"},"
      "{\"type\":3,\"tag\":\"0x7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f\"}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feature_list_t* blk_list = feature_list_new();
  int result = json_features_deserialize(json_obj, false, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(4, feature_list_len(blk_list));
  output_feature_t* feat = feature_list_get_type(blk_list, FEAT_SENDER_TYPE);
  TEST_ASSERT_NOT_NULL(feat);
  feat = feature_list_get_type(blk_list, FEAT_ISSUER_TYPE);
  TEST_ASSERT_NOT_NULL(feat);
  feat = feature_list_get_type(blk_list, FEAT_METADATA_TYPE);
  TEST_ASSERT_NOT_NULL(feat);
  feat = feature_list_get_type(blk_list, FEAT_TAG_TYPE);
  TEST_ASSERT_NOT_NULL(feat);

  // print features
  feature_list_print(blk_list, false, 0);

  cJSON_Delete(json_obj);
  feature_list_free(blk_list);
}

void test_immut_features() {
  char const* const json_res =
      "{\"immutableFeatureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":1,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":2,\"data\":\"0x6d657461646174615f6d657461646174615f6d657461646174615f6d657461646174615f\"},"
      "{\"type\":3,\"tag\":\"0x7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f7461675f\"}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feature_list_t* immut_features = feature_list_new();
  int result = json_features_deserialize(json_obj, true, &immut_features);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(4, feature_list_len(immut_features));
  output_feature_t* immut_feat = feature_list_get_type(immut_features, FEAT_SENDER_TYPE);
  TEST_ASSERT_NOT_NULL(immut_feat);
  immut_feat = feature_list_get_type(immut_features, FEAT_ISSUER_TYPE);
  TEST_ASSERT_NOT_NULL(immut_feat);
  immut_feat = feature_list_get_type(immut_features, FEAT_METADATA_TYPE);
  TEST_ASSERT_NOT_NULL(immut_feat);
  immut_feat = feature_list_get_type(immut_features, FEAT_TAG_TYPE);
  TEST_ASSERT_NOT_NULL(immut_feat);

  // print immutable features
  feature_list_print(immut_features, true, 0);

  cJSON_Delete(json_obj);
  feature_list_free(immut_features);
}

void test_features_unsupported_type() {
  char const* const json_res =
      "{\"featureBlocks\":[{\"type\":4,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  feature_list_t* blk_list = feature_list_new();
  int result = json_features_deserialize(json_obj, false, &blk_list);
  TEST_ASSERT_EQUAL_INT(-1, result);
  TEST_ASSERT_EQUAL_INT(0, feature_list_len(blk_list));

  cJSON_Delete(json_obj);
  feature_list_free(blk_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_feature_sender);
  RUN_TEST(test_feature_issuer);
  RUN_TEST(test_feature_metadata);
  RUN_TEST(test_output_feature_tag);
  RUN_TEST(test_features);
  RUN_TEST(test_immut_features);
  RUN_TEST(test_features_unsupported_type);

  return UNITY_END();
}
