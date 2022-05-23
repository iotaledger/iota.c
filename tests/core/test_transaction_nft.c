// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/models/message.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/unlock_conditions.h"
#include "core/models/payloads/transaction.h"
#include "core/models/signing.h"
#include "unity/unity.h"

// mnemonic seed for testing
byte_t mnemonic_seed[64] = {0x83, 0x7D, 0x69, 0x91, 0x14, 0x64, 0x8E, 0xB,  0x36, 0x78, 0x58, 0xF0, 0xE9,
                            0xA8, 0x4E, 0xF8, 0xBD, 0xFF, 0xD,  0xB7, 0x71, 0x4A, 0xD6, 0x3A, 0xA9, 0x52,
                            0x32, 0x43, 0x56, 0xB6, 0x53, 0x65, 0xD0, 0xE3, 0x9A, 0x30, 0x3A, 0xC5, 0xBB,
                            0xAE, 0x83, 0xD0, 0x13, 0xBC, 0x76, 0xB6, 0xC5, 0xE6, 0xFD, 0xCD, 0x2E, 0x72,
                            0xEC, 0x80, 0x41, 0x33, 0xF3, 0x7B, 0xC0, 0x3E, 0x2A, 0x35, 0xC4, 0xA9};

static byte_t tx_id1[IOTA_TRANSACTION_ID_BYTES] = {0XC9, 0X22, 0X56, 0XA1, 0X97, 0X47, 0X31, 0X5B, 0X22, 0XD5, 0X51,
                                                   0X50, 0X9B, 0X14, 0XB4, 0XD9, 0X72, 0X86, 0XEF, 0XFB, 0X53, 0X51,
                                                   0XAF, 0XE8, 0XCD, 0X1F, 0XA4, 0X79, 0XF6, 0XCC, 0X2D, 0XCC};
static byte_t tx_id2[IOTA_TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  49,  73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 2,   177, 58};
static byte_t tx_id3[IOTA_TRANSACTION_ID_BYTES] = {30,  49,  142, 249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  200, 73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 120, 110, 60};
static byte_t tx_id4[IOTA_TRANSACTION_ID_BYTES] = {20, 29, 142, 249, 151, 34,  243, 150, 40,  39, 76,
                                                   70, 54, 200, 73,  171, 165, 88,  139, 221, 25, 99,
                                                   30, 72, 252, 142, 91,  49,  73,  120, 110, 90};

static byte_t nft_id[NFT_ID_BYTES] = {0x99, 0xf9, 0x13, 0xf4, 0xe0, 0xbc, 0x18, 0xe2, 0xa6, 0x99, 0x5e,
                                      0xa2, 0x4f, 0x4d, 0x6a, 0x46, 0x03, 0x18, 0xfd, 0x4f, 0x4d, 0x6a,
                                      0x13, 0xf4, 0xe0, 0xbc, 0x18, 0xe2, 0xa6, 0x99, 0x5e, 0xa2};

void setUp(void) {}

void tearDown(void) {}

// Transaction input : BASIC OUTPUT with amount x and ED25519 Address Unlock Condition.
// Transaction output 1 : NFT OUTPUT with amount y and NFT ID "0000000000000000000000000000000000000000"
// Transaction output 2 : BASIC OUTPUT with reminder amount x-y
void test_sign_nft_tx_with_basic_input() {
  uint64_t network_id = 2;
  transaction_payload_t* tx_payload = tx_payload_new(network_id);
  TEST_ASSERT_NOT_NULL(tx_payload);

  address_t addr_send, addr_recv;
  ed25519_keypair_t sender_key = {};
  char bech32_sender[65] = {};
  char bech32_receiver[65] = {};
  // IOTA BIP44 Paths: m/44'/4218'/Account'/Change'/Index'
  TEST_ASSERT(address_keypair_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/0'", &sender_key) ==
              0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/0'", &addr_send) == 0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/1'", &addr_recv) == 0);

  char const* const hrp = "atoi";
  address_to_bech32(&addr_send, hrp, bech32_sender, sizeof(bech32_sender));
  address_to_bech32(&addr_recv, hrp, bech32_receiver, sizeof(bech32_receiver));
  printf("sender: %s\nreceiver: %s\n", bech32_sender, bech32_receiver);

  // create a basic output. This data is in real scenario is fetched from a node.
  // create ED25519 address unlock condition for basic output
  unlock_cond_list_t* basic_unlock_conds = condition_list_new();
  unlock_cond_t* basic_unlock_addr = condition_addr_new(&addr_send);
  TEST_ASSERT(condition_list_add(&basic_unlock_conds, basic_unlock_addr) == 0);
  // create output (Will be used for inputs commitment calculation)
  output_basic_t* unspent_basic_output = output_basic_new(3000000, NULL, basic_unlock_conds, NULL);
  TEST_ASSERT_NOT_NULL(unspent_basic_output);

  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();

  // add the output in unspent outputs list to be able to calculate inputs commitment hash
  TEST_ASSERT(utxo_outputs_add(&unspent_outputs, OUTPUT_BASIC, unspent_basic_output) == 0);

  // adding input with tx_id1 (This is a basic output with ed25519 address unlock condition)
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id1, 1) == 0);

  // create signature data. This data is in real scenario is fetched from a node.
  signing_data_list_t* sign_data_list = signing_new();

  // signature data for input
  TEST_ASSERT(signing_data_add(&addr_send, NULL, 0, &sender_key, &sign_data_list) == 0);

  // create nft output with nft_id = "0000000000000000000000000000000000000000000000000000000000000000"
  byte_t nft_id[NFT_ID_BYTES] = {0};

  // create ED25519 address unlock condition for nft output
  unlock_cond_list_t* nft_unlock_conds = condition_list_new();
  unlock_cond_t* nft_unlock_addr = condition_addr_new(&addr_recv);
  TEST_ASSERT(condition_list_add(&nft_unlock_conds, nft_unlock_addr) == 0);

  // create NFT Output with amount 1000000
  output_nft_t* nft_output = output_nft_new(1000000, NULL, nft_id, nft_unlock_conds, NULL, NULL);

  // Add nft output to transaction essence
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_NFT, nft_output));

  // create Basic Output
  output_basic_t* basic_output = output_basic_new(2000000, NULL, basic_unlock_conds, NULL);
  TEST_ASSERT_NOT_NULL(basic_output);

  // Add output to transaction essence
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_BASIC, basic_output));

  // syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_essence_syntactic(tx_payload->essence, cost));
  byte_cost_config_free(cost);

  // calculate inputs commitment
  TEST_ASSERT(tx_essence_inputs_commitment_calculate(tx_payload->essence, unspent_outputs) == 0);

  // add transaction payload to message
  uint8_t protocol_version = 2;
  core_message_t* msg = core_message_new(protocol_version);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload = tx_payload;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(core_message_essence_hash_calc(msg, essence_hash, sizeof(essence_hash)) == 0);

  // sign transaction (generate unlocks)
  TEST_ASSERT(signing_transaction_sign(essence_hash, sizeof(essence_hash), tx_payload->essence->inputs, sign_data_list,
                                       &tx_payload->unlock_blocks) == 0);

  // validate unlocks
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(tx_payload->unlock_blocks));

  unlock_t* unlock = unlock_list_get(tx_payload->unlock_blocks, 0);
  TEST_ASSERT(unlock->type == UNLOCK_SIGNATURE_TYPE);

  core_message_print(msg, 0);

  signing_free(sign_data_list);
  condition_free(nft_unlock_addr);
  condition_list_free(nft_unlock_conds);
  condition_free(basic_unlock_addr);
  condition_list_free(basic_unlock_conds);
  utxo_outputs_free(unspent_outputs);
  output_nft_free(nft_output);
  output_basic_free(unspent_basic_output);
  output_basic_free(basic_output);
  core_message_free(msg);
}

// Transaction input : NFT OUTPUT with amount x and with NFT ID "0000000000000000000000000000000000000000" and ED25519
// Address Unlock Condition.
// Transaction output : NFT OUTPUT with amount x and with NFT ID = BLAKE2b-160 HASH(output_id of UTXO_Input)
void test_sign_nft_tx_with_nft_input() {
  uint64_t network_id = 2;
  transaction_payload_t* tx_payload = tx_payload_new(network_id);
  TEST_ASSERT_NOT_NULL(tx_payload);

  address_t addr_send, addr_recv;
  ed25519_keypair_t sender_key = {};
  char bech32_sender[65] = {};
  char bech32_receiver[65] = {};
  // IOTA BIP44 Paths: m/44'/4218'/Account'/Change'/Index'
  TEST_ASSERT(address_keypair_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/1'", &sender_key) ==
              0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/1'", &addr_send) == 0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/2'", &addr_recv) == 0);

  char const* const hrp = "atoi";
  address_to_bech32(&addr_send, hrp, bech32_sender, sizeof(bech32_sender));
  address_to_bech32(&addr_recv, hrp, bech32_receiver, sizeof(bech32_receiver));
  printf("sender: %s\nreceiver: %s\n", bech32_sender, bech32_receiver);

  // create nft address with nft id "0000000000000000000000000000000000000000"
  address_t input_nft_addr = {};
  input_nft_addr.type = ADDRESS_TYPE_NFT;
  memset(input_nft_addr.address, 0, NFT_ID_BYTES);

  // create an NFT output. This data is in real scenario is fetched from a node.
  // create ED25519 address unlock condition for NFT output
  unlock_cond_list_t* nft_unlock_conds = condition_list_new();
  unlock_cond_t* nft_unlock_addr = condition_addr_new(&addr_send);
  TEST_ASSERT(condition_list_add(&nft_unlock_conds, nft_unlock_addr) == 0);
  // create output (Will be used for inputs commitment calculation)
  output_nft_t* unspent_nft_output =
      output_nft_new(1000000, NULL, input_nft_addr.address, nft_unlock_conds, NULL, NULL);
  TEST_ASSERT_NOT_NULL(unspent_nft_output);

  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();

  // add the output in unspent outputs list to be able to calculate inputs commitment hash
  TEST_ASSERT(utxo_outputs_add(&unspent_outputs, OUTPUT_NFT, unspent_nft_output) == 0);

  // adding input with tx_id2 (This is an nft output with nft id "0000000000000000000000000000000000000000" and ed25519
  // address unlock condition)
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id2, 1) == 0);

  // create signature data. This data is in real scenario is fetched from a node.
  signing_data_list_t* sign_data_list = signing_new();

  // signature data for input
  TEST_ASSERT(signing_data_add(&addr_send, input_nft_addr.address, NFT_ID_BYTES, &sender_key, &sign_data_list) == 0);

  // create nft output
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  // Create NFT ID
  memcpy(nft_addr.address, nft_id, NFT_ID_BYTES);

  // create ed25519 address unlock condition for nft output
  unlock_cond_list_t* nft_output_unlock_conds = condition_list_new();
  unlock_cond_t* nft_output_unlock_addr = condition_addr_new(&addr_recv);
  TEST_ASSERT(condition_list_add(&nft_output_unlock_conds, nft_output_unlock_addr) == 0);

  // create NFT Output with amount 1000000
  output_nft_t* nft_output = output_nft_new(1000000, NULL, nft_addr.address, nft_output_unlock_conds, NULL, NULL);

  // Add output to transaction essence
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_NFT, nft_output));

  // syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_essence_syntactic(tx_payload->essence, cost));
  byte_cost_config_free(cost);

  // calculate inputs commitment
  TEST_ASSERT(tx_essence_inputs_commitment_calculate(tx_payload->essence, unspent_outputs) == 0);

  // add transaction payload to message
  uint8_t protocol_version = 2;
  core_message_t* msg = core_message_new(protocol_version);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload = tx_payload;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(core_message_essence_hash_calc(msg, essence_hash, sizeof(essence_hash)) == 0);

  // sign transaction (generate unlocks)
  TEST_ASSERT(signing_transaction_sign(essence_hash, sizeof(essence_hash), tx_payload->essence->inputs, sign_data_list,
                                       &tx_payload->unlock_blocks) == 0);

  // validate unlocks
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(tx_payload->unlock_blocks));

  unlock_t* unlock = unlock_list_get(tx_payload->unlock_blocks, 0);
  TEST_ASSERT(unlock->type == UNLOCK_SIGNATURE_TYPE);

  core_message_print(msg, 0);

  signing_free(sign_data_list);
  condition_free(nft_unlock_addr);
  condition_list_free(nft_unlock_conds);
  condition_free(nft_output_unlock_addr);
  condition_list_free(nft_output_unlock_conds);
  utxo_outputs_free(unspent_outputs);
  output_nft_free(unspent_nft_output);
  output_nft_free(nft_output);
  core_message_free(msg);
}

// Transaction input 1 : NFT OUTPUT with amount x, non zero NFT ID and ED25519 Address Unlock Condition
// Transaction input 2 : BASIC OUTPUT with amount y and NFT address unlock confition with NFT ID of input 1
// Transaction output : NFT OUTPUT with amount x+y and with NFT ID = NFT ID of input 1
void test_sign_nft_tx_with_nft_and_basic_input() {
  uint64_t network_id = 2;
  transaction_payload_t* tx_payload = tx_payload_new(network_id);
  TEST_ASSERT_NOT_NULL(tx_payload);

  address_t addr_send, addr_recv;
  ed25519_keypair_t sender_key = {};
  char bech32_sender[65] = {};
  char bech32_receiver[65] = {};
  // IOTA BIP44 Paths: m/44'/4218'/Account'/Change'/Index'
  TEST_ASSERT(address_keypair_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/2'", &sender_key) ==
              0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/2'", &addr_send) == 0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/3'", &addr_recv) == 0);

  char const* const hrp = "atoi";
  address_to_bech32(&addr_send, hrp, bech32_sender, sizeof(bech32_sender));
  address_to_bech32(&addr_recv, hrp, bech32_receiver, sizeof(bech32_receiver));
  printf("sender: %s\nreceiver: %s\n", bech32_sender, bech32_receiver);

  // create nft address
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  // create NFT ID
  memcpy(nft_addr.address, nft_id, NFT_ID_BYTES);

  // create an NFT output. This data is in real scenario is fetched from a node.
  // create ED25519 address unlock condition for basic output
  unlock_cond_list_t* nft_unlock_conds = condition_list_new();
  unlock_cond_t* nft_unlock_addr = condition_addr_new(&addr_send);
  TEST_ASSERT(condition_list_add(&nft_unlock_conds, nft_unlock_addr) == 0);
  // create output (Will be used for inputs commitment calculation)
  output_nft_t* unspent_nft_output = output_nft_new(1000000, NULL, nft_addr.address, nft_unlock_conds, NULL, NULL);
  TEST_ASSERT_NOT_NULL(unspent_nft_output);

  // create a basic output. This data is in real scenario is fetched from a node.
  // create NFT address unlock condition for basic output
  unlock_cond_list_t* basic_unlock_conds = condition_list_new();
  unlock_cond_t* basic_unlock_addr = condition_addr_new(&nft_addr);
  TEST_ASSERT(condition_list_add(&basic_unlock_conds, basic_unlock_addr) == 0);
  // create output (Will be used for inputs commitment calculation)
  output_basic_t* unspent_basic_output = output_basic_new(1000000, NULL, basic_unlock_conds, NULL);
  TEST_ASSERT_NOT_NULL(unspent_basic_output);

  utxo_outputs_list_t* unspent_outputs = utxo_outputs_new();

  // add the output in unspent outputs list to be able to calculate inputs commitment hash
  TEST_ASSERT(utxo_outputs_add(&unspent_outputs, OUTPUT_NFT, unspent_nft_output) == 0);
  TEST_ASSERT(utxo_outputs_add(&unspent_outputs, OUTPUT_BASIC, unspent_basic_output) == 0);

  // adding input with tx_id3 (This is an nft output with ED25519 address unlock condition)
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id3, 1) == 0);

  // adding input with tx_id4 (This is a basic output with NFT address unlock condition)
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id4, 1) == 0);

  // create signature data (for both inputs). This data is in real scenario fetched from a node.
  signing_data_list_t* sign_data_list = signing_new();

  // signature data for 1st input
  TEST_ASSERT(signing_data_add(&addr_send, nft_addr.address, NFT_ID_BYTES, &sender_key, &sign_data_list) == 0);

  // signature data for 2nd input
  TEST_ASSERT(signing_data_add(&nft_addr, NULL, 0, NULL, &sign_data_list) == 0);

  // create nft output
  // create ED25519 address unlock condition for nft output
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&addr_recv);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);

  // create NFT Output with amount 2000000
  output_nft_t* nft_output = output_nft_new(2000000, NULL, nft_addr.address, unlock_conds, NULL, NULL);

  // Add output to transaction essence
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_NFT, nft_output));

  // syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_essence_syntactic(tx_payload->essence, cost));
  byte_cost_config_free(cost);

  // calculate inputs commitment
  TEST_ASSERT(tx_essence_inputs_commitment_calculate(tx_payload->essence, unspent_outputs) == 0);

  // add transaction payload to message
  uint8_t protocol_version = 2;
  core_message_t* msg = core_message_new(protocol_version);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload = tx_payload;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(core_message_essence_hash_calc(msg, essence_hash, sizeof(essence_hash)) == 0);

  // sign transaction (generate unlocks)
  TEST_ASSERT(signing_transaction_sign(essence_hash, sizeof(essence_hash), tx_payload->essence->inputs, sign_data_list,
                                       &tx_payload->unlock_blocks) == 0);

  // validate unlocks
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(tx_payload->unlock_blocks));

  unlock_t* unlock = unlock_list_get(tx_payload->unlock_blocks, 0);
  TEST_ASSERT(unlock->type == UNLOCK_SIGNATURE_TYPE);

  unlock = unlock_list_get(tx_payload->unlock_blocks, 1);
  TEST_ASSERT(unlock->type == UNLOCK_NFT_TYPE);

  core_message_print(msg, 0);

  signing_free(sign_data_list);
  condition_free(nft_unlock_addr);
  condition_list_free(nft_unlock_conds);
  condition_free(basic_unlock_addr);
  condition_list_free(basic_unlock_conds);
  condition_free(unlock_addr);
  condition_list_free(unlock_conds);
  utxo_outputs_free(unspent_outputs);
  output_nft_free(unspent_nft_output);
  output_basic_free(unspent_basic_output);
  output_nft_free(nft_output);
  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_sign_nft_tx_with_basic_input);
  RUN_TEST(test_sign_nft_tx_with_nft_input);
  RUN_TEST(test_sign_nft_tx_with_nft_and_basic_input);

  return UNITY_END();
}
