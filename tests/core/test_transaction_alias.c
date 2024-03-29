// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/models/block.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/payloads/transaction.h"
#include "core/models/signing.h"
#include "core/models/unlocks.h"
#include "unity/unity.h"

static byte_t mnemonic_seed[64] = {0x83, 0x7D, 0x69, 0x91, 0x14, 0x64, 0x8E, 0xB,  0x36, 0x78, 0x58, 0xF0, 0xE9,
                                   0xA8, 0x4E, 0xF8, 0xBD, 0xFF, 0xD,  0xB7, 0x71, 0x4A, 0xD6, 0x3A, 0xA9, 0x52,
                                   0x32, 0x43, 0x56, 0xB6, 0x53, 0x65, 0xD0, 0xE3, 0x9A, 0x30, 0x3A, 0xC5, 0xBB,
                                   0xAE, 0x83, 0xD0, 0x13, 0xBC, 0x76, 0xB6, 0xC5, 0xE6, 0xFD, 0xCD, 0x2E, 0x72,
                                   0xEC, 0x80, 0x41, 0x33, 0xF3, 0x7B, 0xC0, 0x3E, 0x2A, 0x35, 0xC4, 0xA9};

static byte_t tx_id0[IOTA_TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  49,  73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 2,   177, 58};
static byte_t tx_id1[IOTA_TRANSACTION_ID_BYTES] = {30,  49,  142, 249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  200, 73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 120, 110, 70};

void setUp(void) {}

void tearDown(void) {}

static output_alias_t* create_output_alias(address_t* address) {
  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();

  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ALIAS_ID_BYTES);
  unlock_cond_t* state_cond = condition_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_cond);

  // random governor address
  iota_crypto_randombytes(test_addr.address, ALIAS_ID_BYTES);
  unlock_cond_t* gov_cond = condition_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_cond);

  TEST_ASSERT(condition_list_add(&unlock_conds, state_cond) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, gov_cond) == 0);

  // create alias Output
  output_alias_t* output =
      output_alias_new(123456789, NULL, address->address, 123456, NULL, 0, 654321, unlock_conds, NULL, NULL);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  condition_free(state_cond);
  condition_free(gov_cond);
  condition_list_free(unlock_conds);

  return output;
}

void test_tx_alias_unlock_funds() {
  // This test case has two inputs (Alias input and Basic input) and creates a new Alias output

  ed25519_keypair_t state_controller_key = {};
  // IOTA BIP44 Paths: m/44'/4218'/Account'/Change'/Index'
  address_keypair_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/0'", &state_controller_key);

  address_t state_controller_addr = {};
  ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/0'", &state_controller_addr);

  uint16_t network_id = 2;
  transaction_payload_t* tx = tx_payload_new(network_id);

  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(alias_addr.address, ALIAS_ID_BYTES);

  // Create signature data (for both inputs). This data is in real scenario fetched from a node.
  signing_data_list_t* sign_data_list = signing_new();

  // add 1. input (alias unspent output) and its signature data
  tx_essence_add_input(tx->essence, 0, tx_id0, 1);
  TEST_ASSERT(signing_data_add(&state_controller_addr, alias_addr.address, ALIAS_ID_BYTES, &state_controller_key,
                               &sign_data_list) == 0);

  // add 2. input (basic unspent output) and its signature data
  tx_essence_add_input(tx->essence, 0, tx_id1, 3);
  TEST_ASSERT(signing_data_add(&alias_addr, NULL, 0, NULL, &sign_data_list) == 0);

  // add alias output to the output list
  output_alias_t* alias_output = create_output_alias(&alias_addr);
  tx_essence_add_output(tx->essence, OUTPUT_ALIAS, alias_output);

  // syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_essence_syntactic(tx->essence, cost));
  byte_cost_config_free(cost);

  // add transaction payload to a block
  uint8_t protocol_ver = 1;
  core_block_t* blk = core_block_new(protocol_ver);
  blk->payload = tx;
  blk->payload_type = CORE_BLOCK_PAYLOAD_TRANSACTION;

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(core_block_essence_hash_calc(blk, essence_hash, sizeof(essence_hash)) == 0);

  // sign transaction (generate unlocks)
  TEST_ASSERT(signing_transaction_sign(essence_hash, sizeof(essence_hash), tx->essence->inputs, sign_data_list,
                                       &tx->unlocks) == 0);

  // validate unlocks
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(tx->unlocks));

  unlock_t* unlock = unlock_list_get(tx->unlocks, 0);
  TEST_ASSERT(unlock->type == UNLOCK_SIGNATURE_TYPE);

  unlock = unlock_list_get(tx->unlocks, 1);
  TEST_ASSERT(unlock->type == UNLOCK_ALIAS_TYPE);

  // print a block
  core_block_print(blk, 0);

  // clean up
  signing_free(sign_data_list);
  output_alias_free(alias_output);
  core_block_free(blk);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_tx_alias_unlock_funds);

  return UNITY_END();
}
