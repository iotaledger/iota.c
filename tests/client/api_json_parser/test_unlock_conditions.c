// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/unlock_conditions.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_unlock_condition_address() {
  char const* const json_res =
      "{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_addr_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, cond_blk_list_len(blk_list));

  unlock_cond_blk_t* cond_unlock = cond_blk_list_get_type(blk_list, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_unlock->type);

  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", ADDRESS_ED25519_HEX_BYTES,
            test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)cond_unlock->block)));

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

void test_unlock_condition_dust_deposit_return() {
  char const* const json_res =
      "{\"type\":1,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}, \"amount\":1337}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_dust_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, cond_blk_list_len(blk_list));

  unlock_cond_blk_t* cond_unlock = cond_blk_list_get_type(blk_list, UNLOCK_COND_DUST);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_unlock->type);

  unlock_cond_dust_t* cond_dust = (unlock_cond_dust_t*)cond_unlock->block;
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", ADDRESS_ED25519_HEX_BYTES,
            test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, cond_dust->addr));
  TEST_ASSERT_EQUAL_UINT64(1337, cond_dust->amount);

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

void test_unlock_condition_timelock() {
  char const* const json_res = "{\"type\":2,\"milestoneIndex\": 123456789, \"unixTime\":987654321}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_timelock_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, cond_blk_list_len(blk_list));

  unlock_cond_blk_t* cond_unlock = cond_blk_list_get_type(blk_list, UNLOCK_COND_TIMELOCK);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond_unlock->type);

  unlock_cond_timelock_t* cond_timelock = (unlock_cond_timelock_t*)cond_unlock->block;
  TEST_ASSERT_EQUAL_UINT32(123456789, cond_timelock->milestone);
  TEST_ASSERT_EQUAL_UINT32(987654321, cond_timelock->time);

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

void test_unlock_condition_expiration() {
  char const* const json_res =
      "{\"type\":3,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}, \"milestoneIndex\": 123456789, "
      "\"unixTime\":987654321}";

  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_expir_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, cond_blk_list_len(blk_list));

  unlock_cond_blk_t* cond_unlock = cond_blk_list_get_type(blk_list, UNLOCK_COND_EXPIRATION);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond_unlock->type);

  unlock_cond_expir_t* cond_expiration = (unlock_cond_expir_t*)cond_unlock->block;
  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", ADDRESS_ED25519_HEX_BYTES,
            test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, cond_expiration->addr));
  TEST_ASSERT_EQUAL_UINT32(123456789, cond_expiration->milestone);
  TEST_ASSERT_EQUAL_UINT32(987654321, cond_expiration->time);

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

void test_unlock_condition_state() {
  char const* const json_res =
      "{\"type\":4,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_state_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, cond_blk_list_len(blk_list));

  unlock_cond_blk_t* cond_unlock = cond_blk_list_get_type(blk_list, UNLOCK_COND_STATE);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STATE, cond_unlock->type);

  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", ADDRESS_ED25519_HEX_BYTES,
            test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)cond_unlock->block)));

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

void test_unlock_condition_governor() {
  char const* const json_res =
      "{\"type\":5,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_governor_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(1, cond_blk_list_len(blk_list));

  unlock_cond_blk_t* cond_unlock = cond_blk_list_get_type(blk_list, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT_NOT_NULL(cond_unlock);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_GOVERNOR, cond_unlock->type);

  address_t test_addr;
  test_addr.type = 0;
  hex_2_bin("194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb", ADDRESS_ED25519_HEX_BYTES,
            test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((address_t*)cond_unlock->block)));

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

void test_unlock_conditions() {
  char const* const json_res =
      "{\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":1,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}, \"amount\":1337},"
      "{\"type\":2,\"milestoneIndex\": 123456789, \"unixTime\":987654321},"
      "{\"type\":3,\"returnAddress\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}, \"milestoneIndex\": 123456789, "
      "\"unixTime\":987654321},"
      "{\"type\":4,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}},"
      "{\"type\":5,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"}}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_list_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(0, result);
  TEST_ASSERT_EQUAL_INT(6, cond_blk_list_len(blk_list));
  unlock_cond_blk_t* cond_block = cond_blk_list_get_type(blk_list, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(cond_block);
  cond_block = cond_blk_list_get_type(blk_list, UNLOCK_COND_DUST);
  TEST_ASSERT_NOT_NULL(cond_block);
  cond_block = cond_blk_list_get_type(blk_list, UNLOCK_COND_TIMELOCK);
  TEST_ASSERT_NOT_NULL(cond_block);
  cond_block = cond_blk_list_get_type(blk_list, UNLOCK_COND_EXPIRATION);
  TEST_ASSERT_NOT_NULL(cond_block);
  cond_block = cond_blk_list_get_type(blk_list, UNLOCK_COND_STATE);
  TEST_ASSERT_NOT_NULL(cond_block);
  cond_block = cond_blk_list_get_type(blk_list, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT_NOT_NULL(cond_block);

  // print unlock conditions
  cond_blk_list_print(blk_list, 0);

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

void test_unlock_conditions_unsupported_type() {
  char const* const json_res =
      "{\"unlockConditions\":[{\"type\":6,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb\"}}]}";
  cJSON* json_obj = cJSON_Parse(json_res);
  TEST_ASSERT_NOT_NULL(json_obj);

  cond_blk_list_t* blk_list = cond_blk_list_new();
  int result = json_cond_blk_list_deserialize(json_obj, &blk_list);
  TEST_ASSERT_EQUAL_INT(-1, result);
  TEST_ASSERT_EQUAL_INT(0, cond_blk_list_len(blk_list));

  cJSON_Delete(json_obj);
  cond_blk_list_free(blk_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_unlock_condition_address);
  RUN_TEST(test_unlock_condition_dust_deposit_return);
  RUN_TEST(test_unlock_condition_timelock);
  RUN_TEST(test_unlock_condition_expiration);
  RUN_TEST(test_unlock_condition_state);
  RUN_TEST(test_unlock_condition_governor);
  RUN_TEST(test_unlock_conditions);
  RUN_TEST(test_unlock_conditions_unsupported_type);

  return UNITY_END();
}
