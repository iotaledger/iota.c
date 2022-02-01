// Copyright 2020 IOTA Stiftungnative_tokens
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/output_alias.h"
#include "core/models/outputs/output_alias.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_alias_output_basic() {
  char const *const json_res =
      "{\"type\":4, \"amount\":1000000,\"nativeTokens\":[],\"aliasId\":\"testAliasID\","
      "\"stateIndex\":12345,\"stateMetadata\":\"testMetadataTestMetadataTestMetadata\",\"foundryCounter\":54321,"
      "\"unlockConditions\":[{\"type\":4,\"address\":{\"type\":16,\"address\":"
      "\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}, "
      "{\"type\":5,\"address\":{\"type\":16,\"address\":\"6dadd4deda97ab502c441e46aa60cfd3d13cbcc9\"}}], "
      "\"blocks\":[]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  transaction_essence_t *essence = tx_essence_new();
  int result = json_output_alias_deserialize(json_obj, essence);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(1, utxo_outputs_count(essence->outputs));
  utxo_output_t *output = utxo_outputs_get(essence->outputs, 0);
  TEST_ASSERT_EQUAL_UINT8(OUTPUT_ALIAS, output->output_type);

  output_alias_t *alias_output = (output_alias_t *)output->output;
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
  tx_essence_free(essence);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_alias_output_basic);

  return UNITY_END();
}
