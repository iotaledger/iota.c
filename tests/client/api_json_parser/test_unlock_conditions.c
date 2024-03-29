// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "client/constants.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_unlock_condition_address() {
  char const* const json_res =
      "{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_addr_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, condition_list_len(cond_list));

  unlock_cond_t* cond_unlock = condition_list_get_type(cond_list, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_unlock->type);

  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)cond_unlock->obj)));

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

void test_unlock_condition_storage_deposit_return() {
  char const* const json_res =
      "{\"type\":1,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}, \"amount\":\"1337\"}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_storage_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, condition_list_len(cond_list));

  unlock_cond_t* cond_unlock = condition_list_get_type(cond_list, UNLOCK_COND_STORAGE);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond_unlock->type);

  unlock_cond_storage_t* cond_storage = (unlock_cond_storage_t*)cond_unlock->obj;
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, cond_storage->addr));
  TEST_ASSERT_EQUAL_UINT64(1337, cond_storage->amount);

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

void test_unlock_condition_timelock() {
  char const* const json_res = "{\"type\":2, \"unixTime\":987654321}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_timelock_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, condition_list_len(cond_list));

  unlock_cond_t* cond_unlock = condition_list_get_type(cond_list, UNLOCK_COND_TIMELOCK);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond_unlock->type);

  unlock_cond_timelock_t* cond_timelock = (unlock_cond_timelock_t*)cond_unlock->obj;
  TEST_ASSERT_EQUAL_UINT32(987654321, cond_timelock->time);

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

void test_unlock_condition_expiration() {
  char const* const json_res =
      "{\"type\":3,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}, "
      "\"unixTime\":987654321}";

  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_expir_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, condition_list_len(cond_list));

  unlock_cond_t* cond_unlock = condition_list_get_type(cond_list, UNLOCK_COND_EXPIRATION);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond_unlock->type);

  unlock_cond_expir_t* cond_expiration = (unlock_cond_expir_t*)cond_unlock->obj;
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, cond_expiration->addr));
  TEST_ASSERT_EQUAL_UINT32(987654321, cond_expiration->time);

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

void test_unlock_condition_state() {
  char const* const json_res =
      "{\"type\":4,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_state_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, condition_list_len(cond_list));

  unlock_cond_t* cond_unlock = condition_list_get_type(cond_list, UNLOCK_COND_STATE);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STATE, cond_unlock->type);

  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)cond_unlock->obj)));

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

void test_unlock_condition_governor() {
  char const* const json_res =
      "{\"type\":5,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_governor_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, condition_list_len(cond_list));

  unlock_cond_t* cond_unlock = condition_list_get_type(cond_list, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_GOVERNOR, cond_unlock->type);

  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES),
            NULL, test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)cond_unlock->obj)));

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

void test_unlock_conditions() {
  char const* const json_res =
      "{\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":1,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}, \"amount\":\"1337\"},"
      "{\"type\":2,\"unixTime\":987654321},"
      "{\"type\":3,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}, "
      "\"unixTime\":987654321},"
      "{\"type\":4,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":5,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":6,\"address\":{\"type\":8,"
      "\"aliasId\":\"0x01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248\"}}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_list_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(7, condition_list_len(cond_list));
  unlock_cond_t* cond = condition_list_get_type(cond_list, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(cond);
  cond = condition_list_get_type(cond_list, UNLOCK_COND_STORAGE);
  TEST_ASSERT_NOT_NULL(cond);
  cond = condition_list_get_type(cond_list, UNLOCK_COND_TIMELOCK);
  TEST_ASSERT_NOT_NULL(cond);
  cond = condition_list_get_type(cond_list, UNLOCK_COND_EXPIRATION);
  TEST_ASSERT_NOT_NULL(cond);
  cond = condition_list_get_type(cond_list, UNLOCK_COND_STATE);
  TEST_ASSERT_NOT_NULL(cond);
  cond = condition_list_get_type(cond_list, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT_NOT_NULL(cond);
  cond = condition_list_get_type(cond_list, UNLOCK_COND_IMMUT_ALIAS);
  TEST_ASSERT_NOT_NULL(cond);

  // print unlock conditions
  condition_list_print(cond_list, 0);

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

void test_unlock_conditions_unsupported_type() {
  char const* const json_res =
      "{\"unlockConditions\":[{\"type\":7,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  unlock_cond_list_t* cond_list = condition_list_new();
  int result = json_condition_list_deserialize(json_obj, &cond_list);
  TEST_ASSERT_EQUAL_INT(-1, result);
  TEST_ASSERT_EQUAL_INT(0, condition_list_len(cond_list));

  cJSON_Delete(json_obj);
  condition_list_free(cond_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_unlock_condition_address);
  RUN_TEST(test_unlock_condition_storage_deposit_return);
  RUN_TEST(test_unlock_condition_timelock);
  RUN_TEST(test_unlock_condition_expiration);
  RUN_TEST(test_unlock_condition_state);
  RUN_TEST(test_unlock_condition_governor);
  RUN_TEST(test_unlock_conditions);
  RUN_TEST(test_unlock_conditions_unsupported_type);

  return UNITY_END();
}
