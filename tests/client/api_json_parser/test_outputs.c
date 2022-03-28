// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/outputs.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_outputs_empty() {
  char const *const json_res = "{\"outputs\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch output array
  cJSON *output_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_OUTPUTS);
  TEST_ASSERT_TRUE(cJSON_IsArray(output_data));

  utxo_outputs_list_t *output_list = utxo_outputs_new();
  int result = json_outputs_deserialize(output_data, &output_list);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(0, utxo_outputs_count(output_list));

  cJSON_Delete(json_obj);
  utxo_outputs_free(output_list);
}

void test_parse_outputs() {
  char const *const json_res =
      "{\"outputs\":["
      // basic output
      "{\"type\":3,\"amount\":1000000,\"nativeTokens\":[{\"id\":"
      "\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"7598347598347598\"}],\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}},{\"type\":1,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"amount\":800000},{\"type\":2,"
      "\"milestoneIndex\":45598,\"unixTime\":123123},{\"type\":3,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"milestoneIndex\":45598,\"unixTime\":"
      "123123}],\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":\"metadataTest_"
      "metadataTest_metadataTest_metadataTest_metadataTest\"},{\"type\":3,\"tag\":\"tagTest_tagTest_tagTest_"
      "tagTest_tagTest_tagTest\"}]},"
      // alias output
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
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,"
      "\"data\":\"89dfjg0s9djfgdsfgjsdfg98sjdf98g23id0gjf0sdffgj098sdgcvb0xcuubx9b\"}],\"immutableFeatureBlocks\":[{"
      "\"type\":1,\"address\":{\"type\":0,"
      "\"pubKeyHash\":\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"immutableMetadataTest_immutableMetadataTest_immutableMetadataTest_ImmutableMetadataTest\"}]},"
      // foundry output
      "{\"type\":5,\"amount\":1000000,\"nativeTokens\":[{\"id\":"
      "\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\",\"amount\":"
      "\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"7598347598347598\"}],\"serialNumber\":123456,\"tokenTag\":\"TokenTAGDemo\",\"maximumSupply\":"
      "\"30000000000000000000000000000000000000000\",\"tokenScheme\":{\"type\":0,\"mintedTokens\":"
      "\"20000000000000000000000000000000000000000\",\"meltedTokens\":"
      "\"10000000000000000000000000000000000000000\",\"maximumSupply\":"
      "\"30000000000000000000000000000000000000000\"},\"unlockConditions\":[{\"type\":6,"
      "\"address\":{"
      "\"type\":8,\"aliasId\":\"194eb32b9b6c61207192c7073562a0b3adf50a7c\"}}],\"featureBlocks\":[{\"type\":2,\"data\":"
      "\"metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata_metadata\"}],"
      "\"immutableFeatureBlocks\":[{\"type\":2,\"data\":"
      "\"immutable_metadata_immutable_metadata_immutable_metadata_immutable_metadata_immutable_metadata\"}]},"
      // NFT output
      "{\"type\":6,\"amount\":1000000,\"nativeTokens\":[{\"id\":"
      "\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"7598347598347598\"}],\"nftId\":\"bebc45994f6bd9394f552b62c6e370ce1ab52d2e\",\"unlockConditions\":[{\"type\":0,"
      "\"address\":{\"type\":16,\"nftId\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}},{\"type\":1,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"amount\":800000},{\"type\":2,"
      "\"milestoneIndex\":45598,\"unixTime\":123123},{\"type\":3,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"},\"milestoneIndex\":45598,\"unixTime\":"
      "123123}],\"featureBlocks\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"metadataTest_metadataTest_metadataTest_metadataTest_metadataTest\"},{\"type\":3,\"tag\":\"tagTest_tagTest_"
      "tagTest_tagTest_tagTest_tagTest\"}],\"immutableFeatureBlocks\":[{\"type\":1,\"address\":{\"type\":0,"
      "\"pubKeyHash\":\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},{\"type\":2,\"data\":"
      "\"immutableMetadataTest_immutableMetadataTest_immutableMetadataTest_ImmutableMetadataTest\"}]}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  // fetch output array
  cJSON *output_data = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_OUTPUTS);
  TEST_ASSERT_TRUE(cJSON_IsArray(output_data));

  utxo_outputs_list_t *output_list = utxo_outputs_new();
  int result = json_outputs_deserialize(output_data, &output_list);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(4, utxo_outputs_count(output_list));

  // check basic output
  utxo_output_t *output = utxo_outputs_get(output_list, 0);
  TEST_ASSERT_EQUAL_UINT8(OUTPUT_BASIC, output->output_type);

  // check alias output
  output = utxo_outputs_get(output_list, 1);
  TEST_ASSERT_EQUAL_UINT8(OUTPUT_ALIAS, output->output_type);

  // check foundry output
  output = utxo_outputs_get(output_list, 2);
  TEST_ASSERT_EQUAL_UINT8(OUTPUT_FOUNDRY, output->output_type);

  // check NFT output
  output = utxo_outputs_get(output_list, 3);
  TEST_ASSERT_EQUAL_UINT8(OUTPUT_NFT, output->output_type);

  // print output list
  utxo_outputs_print(output_list, 0);

  cJSON_Delete(json_obj);
  utxo_outputs_free(output_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_outputs_empty);
  RUN_TEST(test_parse_outputs);

  return UNITY_END();
}
