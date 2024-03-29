// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/storage_deposit.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_storage_deposit_check_sufficient_output_deposit_null_parameters() {
  byte_cost_config_t config;
  bool result = storage_deposit_check(&config, OUTPUT_BASIC, NULL);
  TEST_ASSERT_FALSE(result);

  output_basic_t output;
  result = storage_deposit_check(NULL, OUTPUT_BASIC, &output);
  TEST_ASSERT_FALSE(result);
}

void test_storage_deposit_check_sufficient_output_deposit_unsupported_type() {
  byte_cost_config_t config;
  output_basic_t output;

  bool result = storage_deposit_check(&config, OUTPUT_SINGLE_OUTPUT, &output);
  TEST_ASSERT_FALSE(result);

  result = storage_deposit_check(&config, OUTPUT_DUST_ALLOWANCE, &output);
  TEST_ASSERT_FALSE(result);

  result = storage_deposit_check(&config, OUTPUT_TREASURY, &output);
  TEST_ASSERT_FALSE(result);
}

void test_storage_deposit_check_sufficient_output_deposit() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);

  byte_cost_config_t* config = byte_cost_config_default_new();

  // 20i will be sent
  uint64_t amount = 234000;
  uint64_t storage_deposit = 233980;

  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&test_addr);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_t* unlock_storage = condition_storage_new(&test_addr, storage_deposit);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);

  output_basic_t* output = output_basic_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check(config, OUTPUT_BASIC, output);
  TEST_ASSERT_TRUE(result);

  byte_cost_config_free(config);
  condition_free(unlock_addr);
  condition_free(unlock_storage);
  condition_list_free(unlock_conds);
  output_basic_free(output);
}

void test_storage_deposit_check_sufficient_output_deposit_native_tokens_sent() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);

  byte_cost_config_t* config = byte_cost_config_default_new();

  // In case that only some native tokens are sent, amount and storage deposit are the same
  uint64_t amount = 234000;
  uint64_t storage_deposit = 234000;

  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&test_addr);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_t* unlock_storage = condition_storage_new(&test_addr, storage_deposit);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);

  output_basic_t* output = output_basic_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check(config, OUTPUT_BASIC, output);
  TEST_ASSERT_TRUE(result);

  byte_cost_config_free(config);
  condition_free(unlock_addr);
  condition_free(unlock_storage);
  condition_list_free(unlock_conds);
  output_basic_free(output);
}

void test_storage_deposit_check_sufficient_output_amount_too_low() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);

  byte_cost_config_t* config = byte_cost_config_default_new();

  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&test_addr);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);

  output_basic_t* output = output_basic_new(212999, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check(config, OUTPUT_BASIC, output);
  TEST_ASSERT_FALSE(result);

  byte_cost_config_free(config);
  condition_free(unlock_addr);
  condition_list_free(unlock_conds);
  output_basic_free(output);
}

void test_storage_deposit_check_sufficient_output_return_storage_deposit_too_low() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);

  byte_cost_config_t* config = byte_cost_config_default_new();

  uint64_t amount = 234000;
  uint64_t storage_deposit = 212999;  // to low return storage deposit which is 213000

  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&test_addr);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_t* unlock_storage = condition_storage_new(&test_addr, storage_deposit);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);

  output_basic_t* output = output_basic_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check(config, OUTPUT_BASIC, output);
  TEST_ASSERT_FALSE(result);

  byte_cost_config_free(config);
  condition_free(unlock_addr);
  condition_free(unlock_storage);
  condition_list_free(unlock_conds);
  output_basic_free(output);
}

void test_storage_deposit_check_sufficient_output_return_storage_deposit_too_high() {
  // create random ED25519 address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);

  byte_cost_config_t* config = byte_cost_config_default_new();

  // storage deposit will exceed outputs amount
  uint64_t amount = 234000;
  uint64_t storage_deposit = 234001;

  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&test_addr);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  unlock_cond_t* unlock_storage = condition_storage_new(&test_addr, storage_deposit);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);

  output_basic_t* output = output_basic_new(amount, NULL, unlock_conds, NULL);

  bool result = storage_deposit_check(config, OUTPUT_BASIC, output);
  TEST_ASSERT_FALSE(result);

  byte_cost_config_free(config);
  condition_free(unlock_addr);
  condition_free(unlock_storage);
  condition_list_free(unlock_conds);
  output_basic_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit_null_parameters);
  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit_unsupported_type);
  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit);
  RUN_TEST(test_storage_deposit_check_sufficient_output_deposit_native_tokens_sent);
  RUN_TEST(test_storage_deposit_check_sufficient_output_amount_too_low);
  RUN_TEST(test_storage_deposit_check_sufficient_output_return_storage_deposit_too_low);
  RUN_TEST(test_storage_deposit_check_sufficient_output_return_storage_deposit_too_high);

  return UNITY_END();
}
