// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/common.h"
#include "client/constants.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_parse_ed25519_address() {
  char const* const json_res =
      "{\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  address_t address;
  int result = json_parser_common_address_deserialize(json_obj, JSON_KEY_ADDR, &address);
  TEST_ASSERT_EQUAL_INT(0, result);

  address_t test_addr;
  test_addr.type = ADDRESS_TYPE_ED25519;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, &address));

  cJSON_Delete(json_obj);
}

void test_parse_alias_address() {
  char const* const json_res =
      "{\"address\":{\"type\":8,\"aliasId\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  address_t address;
  int result = json_parser_common_address_deserialize(json_obj, JSON_KEY_ADDR, &address);
  TEST_ASSERT_EQUAL_INT(0, result);

  address_t test_addr;
  test_addr.type = ADDRESS_TYPE_ALIAS;
  hex_2_bin("ad32258255e7cf927a4833f457f220b7187cf975", BIN_TO_HEX_BYTES(ALIAS_ID_BYTES), NULL, test_addr.address,
            ALIAS_ID_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, &address));

  cJSON_Delete(json_obj);
}

void test_parse_nft_address() {
  char const* const json_res =
      "{\"address\":{\"type\":16,\"nftId\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  address_t address;
  int result = json_parser_common_address_deserialize(json_obj, JSON_KEY_ADDR, &address);
  TEST_ASSERT_EQUAL_INT(0, result);

  address_t test_addr;
  test_addr.type = ADDRESS_TYPE_NFT;
  hex_2_bin("ad32258255e7cf927a4833f457f220b7187cf975", BIN_TO_HEX_BYTES(NFT_ID_BYTES), NULL, test_addr.address,
            NFT_ID_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, &address));

  cJSON_Delete(json_obj);
}

void test_parse_unsupported_address_type() {
  char const* const json_res =
      "{\"address\":{\"type\":10,\"address\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  address_t address;
  int result = json_parser_common_address_deserialize(json_obj, JSON_KEY_ADDR, &address);
  TEST_ASSERT_EQUAL_INT(-1, result);

  cJSON_Delete(json_obj);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_parse_ed25519_address);
  RUN_TEST(test_parse_alias_address);
  RUN_TEST(test_parse_nft_address);
  RUN_TEST(test_parse_unsupported_address_type);

  return UNITY_END();
}
