// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/native_tokens.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_native_tokens() {
  char const *const json_res =
      "{\"nativeTokens\":[{\"id\":\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":"
      "\"123456789\"},{\"id\":"
      "\"18e781c2e4503f9e25206e21b2bddfd39995bdd0c40000000000000000500000000000000000\",\"amount\":"
      "\"786345384765384756384584736584938475938475983475982375498374598374985756\"}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  native_tokens_list_t *tokens = native_tokens_new();
  int result = json_native_tokens_deserialize(json_obj, &tokens);
  TEST_ASSERT_EQUAL_INT(0, result);

  TEST_ASSERT_EQUAL_UINT16(3, native_tokens_count(tokens));

  // check 1st native token
  byte_t token_id[NATIVE_TOKEN_ID_BYTES];
  hex_2_bin("08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), token_id, NATIVE_TOKEN_ID_BYTES);
  native_token_t *token = native_tokens_find_by_id(tokens, token_id);
  TEST_ASSERT_NOT_NULL(token);
  uint256_t *amount = uint256_from_str("93847598347598347598347598");
  TEST_ASSERT_EQUAL_INT(0, uint256_equal(amount, token->amount));
  free(amount);

  // check 2nd native token
  hex_2_bin("09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), token_id, NATIVE_TOKEN_ID_BYTES);
  token = native_tokens_find_by_id(tokens, token_id);
  TEST_ASSERT_NOT_NULL(token);
  amount = uint256_from_str("123456789");
  TEST_ASSERT_EQUAL_INT(0, uint256_equal(amount, token->amount));
  free(amount);

  // check 3rd native token
  hex_2_bin("18e781c2e4503f9e25206e21b2bddfd39995bdd0c40000000000000000500000000000000000",
            BIN_TO_HEX_BYTES(NATIVE_TOKEN_ID_BYTES), token_id, NATIVE_TOKEN_ID_BYTES);
  token = native_tokens_find_by_id(tokens, token_id);
  TEST_ASSERT_NOT_NULL(token);
  amount = uint256_from_str("786345384765384756384584736584938475938475983475982375498374598374985756");
  TEST_ASSERT_EQUAL_INT(0, uint256_equal(amount, token->amount));
  free(amount);

  // print native tokens
  native_tokens_print(tokens, 0);

  cJSON_Delete(json_obj);
  native_tokens_free(tokens);
}

void test_parse_native_tokens_failed() {
  char const *const json_res =
      "{\"nativeTokens\":[{\"id\":\"08e781c2e4503f9e25207e21b2bddfd39995bdd0c40000000000000030000000000000000000\","
      "\"amount\":\"93847598347598347598347598\"},{\"id\":"
      "\"09e731c2e4503d9e25207e21b2bddfd39995bdd0c40000000000000000070000000000000000\",\"amount\":0}]}";

  cJSON *json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  native_tokens_list_t *tokens = native_tokens_new();
  int result = json_native_tokens_deserialize(json_obj, &tokens);
  TEST_ASSERT_EQUAL_INT(-1, result);

  cJSON_Delete(json_obj);
  native_tokens_free(tokens);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_native_tokens);
  RUN_TEST(test_parse_native_tokens_failed);

  return UNITY_END();
}
