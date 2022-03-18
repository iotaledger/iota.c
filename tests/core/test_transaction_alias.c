// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/outputs.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "core/models/unlock_block.h"

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

/*static output_basic_t* create_output_basic() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  // create Native Tokens
  native_tokens_list_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_sender(&feat_blocks, &addr);

  // create Unlock Conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&addr);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, native_tokens, unlock_conds, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(native_tokens);
  feat_blk_list_free(feat_blocks);
  cond_blk_free(unlock_addr);
  cond_blk_list_free(unlock_conds);

  return output;
}*/

static output_alias_t* create_output_alias() {
  // create random alias ID
  byte_t alias_id[ALIAS_ID_BYTES];
  iota_crypto_randombytes(alias_id, ALIAS_ID_BYTES);

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();

  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ALIAS_ID_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);

  // random governor address
  iota_crypto_randombytes(test_addr.address, ALIAS_ID_BYTES);
  unlock_cond_blk_t* gov_block = cond_blk_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_block);

  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, gov_block) == 0);

  // create alias Output
  output_alias_t* output =
      output_alias_new(123456789, NULL, alias_id, 123456, NULL, 0, 654321, unlock_conds, NULL, NULL);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  cond_blk_list_free(unlock_conds);

  return output;
}

void test_tx_alias_create() {
  ed25519_keypair_t sender_key = {};
  // IOTA BIP44 Paths: m/44'/4128'/Account'/Change'/Index'
  TEST_ASSERT(address_keypair_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/0'", &sender_key) ==
              0);

  uint16_t network_id = 2;
  transaction_payload_t* tx = tx_payload_new(network_id);

  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(alias_addr.address, ALIAS_ID_BYTES);

  // add input with tx_id0
  TEST_ASSERT(tx_essence_add_input(tx->essence, 0, tx_id0, 1, &sender_key, &alias_addr) == 0);

  // add input with tx_id1
  TEST_ASSERT(tx_essence_add_input(tx->essence, 0, tx_id1, 1, NULL, &alias_addr) == 0);

  // add alias output to the output list
  output_alias_t* alias_output = create_output_alias();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx->essence, OUTPUT_ALIAS, alias_output));

  // get count of input list
  TEST_ASSERT_EQUAL_UINT16(2, utxo_inputs_count(tx->essence->inputs));

  // get count of output list
  TEST_ASSERT_EQUAL_UINT16(1, utxo_outputs_count(tx->essence->outputs));

  // syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_essence_syntactic(tx->essence, cost));
  byte_cost_config_free(cost);

  // add transaction payload to message
  uint8_t protocol_ver = 1;
  core_message_t* msg = core_message_new(protocol_ver);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload = tx;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;

  // sign transaction
  TEST_ASSERT(core_message_sign_transaction(msg) == 0);

  // print core message transaction
  core_message_print(msg, 0);

  // clean up
  output_alias_free(alias_output);
  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_tx_alias_create);

  return UNITY_END();
}
