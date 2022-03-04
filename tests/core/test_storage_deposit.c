// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/message.h"
#include "core/models/outputs/storage_deposit.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_storage_deposit_create_new_config() {
  uint16_t byte_cost = (uint16_t)123456;
  uint8_t byte_factor_data = 111;
  uint8_t byte_factor_key = 222;
  uint16_t byte_offset = (IOTA_OUTPUT_ID_BYTES * byte_factor_key) + (IOTA_MESSAGE_ID_BYTES * byte_factor_data) +
                         (sizeof(uint32_t) * byte_factor_data) + (sizeof(uint32_t) * byte_factor_data);

  byte_cost_config_t* config = storage_deposit_new_config(byte_cost, byte_factor_data, byte_factor_key);

  TEST_ASSERT_EQUAL_UINT16(byte_cost, config->v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(byte_factor_data, config->v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(byte_factor_key, config->v_byte_factor_key);
  TEST_ASSERT_EQUAL_UINT16(byte_offset, config->v_byte_offset);

  free(config);
}

void test_storage_deposit_create_new_default_config() {
  byte_cost_config_t* config = storage_deposit_new_default_config();

  TEST_ASSERT_EQUAL_UINT16(500, config->v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(1, config->v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(10, config->v_byte_factor_key);
  TEST_ASSERT_EQUAL_UINT16(380, config->v_byte_offset);

  free(config);
}

void test_storage_deposit_check_sufficient_output_deposit_null_parameters() {
  byte_cost_config_t config;
  bool result = storage_deposit_check_sufficient_output_deposit(&config, OUTPUT_EXTENDED, NULL);
  TEST_ASSERT_FALSE(result);

  output_extended_t output;
  result = storage_deposit_check_sufficient_output_deposit(NULL, OUTPUT_EXTENDED, &output);
  TEST_ASSERT_FALSE(result);
}

void test_storage_deposit_check_sufficient_output_deposit_unsupported_type() {
  byte_cost_config_t config;
  output_extended_t output;

  bool result = storage_deposit_check_sufficient_output_deposit(&config, OUTPUT_SINGLE_OUTPUT, &output);
  TEST_ASSERT_FALSE(result);

  result = storage_deposit_check_sufficient_output_deposit(&config, OUTPUT_DUST_ALLOWANCE, &output);
  TEST_ASSERT_FALSE(result);

  result = storage_deposit_check_sufficient_output_deposit(&config, OUTPUT_TREASURY, &output);
  TEST_ASSERT_FALSE(result);
}

void test_storage_deposit_check_sufficient_output_deposit() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);

  byte_cost_config_t* config = storage_deposit_new_default_config();

  // 20i will be sent
  uint64_t amount = 44400;
  uint64_t storage_deposit = 44380;

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&test_addr);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_blk_t* unlock_dust = cond_blk_dust_new(&test_addr, storage_deposit);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);

  output_extended_t* output = output_extended_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check_sufficient_output_deposit(config, OUTPUT_EXTENDED, output);
  TEST_ASSERT_TRUE(result);

  free(config);
  cond_blk_free(unlock_addr);
  cond_blk_free(unlock_dust);
  cond_blk_list_free(unlock_conds);
  output_extended_free(output);
}

void test_storage_deposit_check_sufficient_output_deposit_native_tokens_sent() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);

  byte_cost_config_t* config = storage_deposit_new_default_config();

  // In case that only some native tokens are sent, amount and storage deposit are the same
  uint64_t amount = 44400;
  uint64_t storage_deposit = 44400;

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&test_addr);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_blk_t* unlock_dust = cond_blk_dust_new(&test_addr, storage_deposit);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);

  output_extended_t* output = output_extended_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check_sufficient_output_deposit(config, OUTPUT_EXTENDED, output);
  TEST_ASSERT_TRUE(result);

  free(config);
  cond_blk_free(unlock_addr);
  cond_blk_free(unlock_dust);
  cond_blk_list_free(unlock_conds);
  output_extended_free(output);
}

void test_storage_deposit_check_sufficient_output_amount_too_low() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);

  byte_cost_config_t* config = storage_deposit_new_default_config();

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&test_addr);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);

  output_extended_t* output = output_extended_new(23379, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check_sufficient_output_deposit(config, OUTPUT_EXTENDED, output);
  TEST_ASSERT_FALSE(result);

  free(config);
  cond_blk_free(unlock_addr);
  cond_blk_list_free(unlock_conds);
  output_extended_free(output);
}

void test_storage_deposit_check_sufficient_output_return_storage_deposit_too_low() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);

  byte_cost_config_t* config = storage_deposit_new_default_config();

  uint64_t amount = 44400;
  uint64_t storage_deposit = 23379;  // to low return storage deposit which is 23380

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&test_addr);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_blk_t* unlock_dust = cond_blk_dust_new(&test_addr, storage_deposit);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);

  output_extended_t* output = output_extended_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check_sufficient_output_deposit(config, OUTPUT_EXTENDED, output);
  TEST_ASSERT_FALSE(result);

  free(config);
  cond_blk_free(unlock_addr);
  cond_blk_free(unlock_dust);
  cond_blk_list_free(unlock_conds);
  output_extended_free(output);
}

void test_storage_deposit_check_sufficient_output_not_microtransaction() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);

  byte_cost_config_t* config = storage_deposit_new_default_config();

  // 1000000i will be sent
  uint64_t amount = 1044380;
  uint64_t storage_deposit = 44380;

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&test_addr);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_blk_t* unlock_dust = cond_blk_dust_new(&test_addr, storage_deposit);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);

  output_extended_t* output = output_extended_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check_sufficient_output_deposit(config, OUTPUT_EXTENDED, output);
  TEST_ASSERT_FALSE(result);

  free(config);
  cond_blk_free(unlock_addr);
  cond_blk_free(unlock_dust);
  cond_blk_list_free(unlock_conds);
  output_extended_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_storage_deposit_create_new_config);
  RUN_TEST(test_storage_deposit_create_new_default_config);
  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit_null_parameters);
  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit_unsupported_type);
  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit);
  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit_native_tokens_sent);
  RUN_TEST(test_storage_deposit_check_sufficient_output_amount_too_low);
  RUN_TEST(test_storage_deposit_check_sufficient_output_return_storage_deposit_too_low);
  RUN_TEST(test_storage_deposit_check_sufficient_output_not_microtransaction);

  return UNITY_END();
}
