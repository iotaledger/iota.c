// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <unity/unity.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/message.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"

#define DATA_LEN 128
char const* const tag_str = "HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD";

static byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
    0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56, 0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,
    0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75, 0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
static byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {
    0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC, 0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41, 0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A,
    0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0, 0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
static byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {
    0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E, 0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE,
    0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42, 0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};

byte_t test_meta[] = "Test metadata...";
byte_t test_immut_meta[] = "Test immutable metadata...";

static byte_t tx_id0[IOTA_TRANSACTION_ID_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t tx_id1[IOTA_TRANSACTION_ID_BYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                                   255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                                   255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
static byte_t tx_id2[IOTA_TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  49,  73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 2,   177, 58};
static byte_t tx_id3[IOTA_TRANSACTION_ID_BYTES] = {30,  49,  142, 249, 151, 44,  243, 150, 40,  39, 46,
                                                   190, 54,  200, 73,  171, 165, 88,  139, 221, 25, 199,
                                                   90,  172, 252, 142, 91,  179, 113, 120, 110, 70};

static byte_t inputs_commitment[CRYPTO_BLAKE2B_256_HASH_BYTES] = {
    0x9F, 0x0A, 0x15, 0x33, 0xB9, 0x1A, 0xD7, 0x55, 0x16, 0x45, 0xDD, 0x07, 0xD1, 0xC2, 0x18, 0x33,
    0xFF, 0xF8, 0x1E, 0x74, 0xAF, 0x49, 0x2A, 0xF0, 0xCA, 0x6D, 0x99, 0xAB, 0x7F, 0x63, 0xB5, 0xC9};

static byte_t test_pub_key[ED_PUBLIC_KEY_BYTES] = {0xe7, 0x45, 0x3d, 0x64, 0x4d, 0x7b, 0xe6, 0x70, 0x64, 0x80, 0x15,
                                                   0x74, 0x28, 0xd9, 0x68, 0x87, 0x2e, 0x38, 0x9c, 0x7b, 0x27, 0x62,
                                                   0xd1, 0x4b, 0xbe, 0xc,  0xa4, 0x6b, 0x91, 0xde, 0xa4, 0xc4};
static byte_t test_sig[ED_SIGNATURE_BYTES] = {
    0x74, 0x9,  0x52, 0x4c, 0xa4, 0x4,  0xfb, 0x5e, 0x51, 0xe3, 0xc6, 0x65, 0xf1, 0x1f, 0xa6, 0x61,
    0x4,  0xc3, 0xe,  0x8,  0xe9, 0x0,  0x38, 0x4f, 0xdd, 0xeb, 0x5b, 0x93, 0xb6, 0xed, 0xa0, 0x54,
    0xc5, 0x3,  0x3e, 0xbd, 0xd4, 0xd8, 0xa7, 0xa,  0x7b, 0xa8, 0xbb, 0xcc, 0x7a, 0x34, 0x4d, 0x56,
    0xe2, 0xba, 0x11, 0xd2, 0x2a, 0xf3, 0xab, 0xe4, 0x6e, 0x99, 0x21, 0x56, 0x25, 0x73, 0xf2, 0x62};

void setUp(void) {}

void tearDown(void) {}

static output_basic_t* create_output_basic() {
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

  // create Features
  feature_list_t* feat_list = feature_list_new();
  feature_list_add_sender(&feat_list, &addr);

  // create Unlock Conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&addr);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, native_tokens, unlock_conds, feat_list);
  TEST_ASSERT_NOT_NULL(output);

  uint256_free(amount1);
  uint256_free(amount2);
  uint256_free(amount3);
  native_tokens_free(native_tokens);
  feature_list_free(feat_list);
  condition_free(unlock_addr);
  condition_list_free(unlock_conds);

  return output;
}

static output_alias_t* create_output_alias() {
  native_tokens_list_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create random alias ID
  byte_t alias_id[ALIAS_ID_BYTES];
  iota_crypto_randombytes(alias_id, ALIAS_ID_BYTES);

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

  // create Feature Blocks
  feature_list_t* feat_list = feature_list_new();
  TEST_ASSERT(feature_list_add_metadata(&feat_list, test_meta, sizeof(test_meta)) == 0);

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ED25519_PUBKEY_BYTES);

  // create Immutable Feature Blocks
  feature_list_t* immut_feat_list = feature_list_new();
  TEST_ASSERT(feature_list_add_metadata(&immut_feat_list, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feature_list_add_issuer(&immut_feat_list, &issuer_addr) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta),
                                            654321, unlock_conds, feat_list, immut_feat_list);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  uint256_free(amount1);
  uint256_free(amount2);
  uint256_free(amount3);
  condition_free(state_cond);
  condition_free(gov_cond);
  native_tokens_free(native_tokens);
  condition_list_free(unlock_conds);
  feature_list_free(feat_list);
  feature_list_free(immut_feat_list);

  return output;
}

static output_foundry_t* create_output_foundry() {
  // create Native Tokens
  native_tokens_list_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create minted tokens
  uint256_t* minted_tokens = uint256_from_str("200000000");
  // create melted tokens
  uint256_t* melted_tokens = uint256_from_str("100000000");
  // create maximum supply
  uint256_t* max_supply = uint256_from_str("300000000");

  // create random Alias address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(addr.address, ALIAS_ID_BYTES);

  // create token_scheme
  token_scheme_t* token_scheme = token_scheme_simple_new(minted_tokens, melted_tokens, max_supply);

  // create Foundry Output
  output_foundry_t* output = output_foundry_new(&addr, 123456789, native_tokens, 22, token_scheme, test_meta,
                                                sizeof(test_meta), test_immut_meta, sizeof(test_immut_meta));

  uint256_free(amount1);
  uint256_free(amount2);
  uint256_free(amount3);
  uint256_free(minted_tokens);
  uint256_free(melted_tokens);
  uint256_free(max_supply);
  token_scheme_free(token_scheme);
  native_tokens_free(native_tokens);

  return output;
}

static output_nft_t* create_output_nft() {
  // create random NFT address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, NFT_ID_BYTES);

  native_tokens_list_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create NFT ID
  byte_t nft_id[NFT_ID_BYTES];
  iota_crypto_randombytes(nft_id, NFT_ID_BYTES);

  // create Unlock Conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  unlock_cond_t* unlock_addr = condition_addr_new(&addr);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  condition_free(unlock_addr);

  // create random sender address
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ED25519_PUBKEY_BYTES);
  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ED25519_PUBKEY_BYTES);
  // create Feature Blocks
  feature_list_t* feat_list = feature_list_new();
  TEST_ASSERT(feature_list_add_sender(&feat_list, &sender_addr) == 0);
  TEST_ASSERT(feature_list_add_metadata(&feat_list, test_meta, sizeof(test_meta)) == 0);
  // create Immutable Feature Blocks
  feature_list_t* immut_feat_list = feature_list_new();
  TEST_ASSERT(feature_list_add_metadata(&immut_feat_list, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feature_list_add_issuer(&immut_feat_list, &issuer_addr) == 0);

  // create NFT Output
  output_nft_t* output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_list, immut_feat_list);

  // clean up
  uint256_free(amount1);
  uint256_free(amount2);
  uint256_free(amount3);
  native_tokens_free(native_tokens);
  condition_list_free(unlock_conds);
  feature_list_free(feat_list);
  feature_list_free(immut_feat_list);

  return output;
}

void test_tx_essence() {
  uint16_t network_id = 2;
  transaction_essence_t* es = tx_essence_new(network_id);
  TEST_ASSERT_NOT_NULL(es);

  // get count of empty input list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(es->inputs));

  // get count of empty output list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_outputs_count(es->outputs));

  // Check serialize len for empty essence
  TEST_ASSERT(tx_essence_serialize_length(es) == 0);

  // print empty essence
  tx_essence_print(es, 0);

  // test for -1 if transaction id is null
  TEST_ASSERT(tx_essence_add_input(es, 0, NULL, 1) == -1);

  // add input with tx_id0
  TEST_ASSERT(tx_essence_add_input(es, 0, tx_id0, 1) == 0);

  // add input with tx_id1
  TEST_ASSERT(tx_essence_add_input(es, 0, tx_id1, 2) == 0);

  // add input with tx_id2
  TEST_ASSERT(tx_essence_add_input(es, 0, tx_id2, 3) == 0);

  // add inputs commitment
  TEST_ASSERT_NOT_NULL(memcpy(&es->inputs_commitment, &inputs_commitment, CRYPTO_BLAKE2B_256_HASH_BYTES));

  // test for -1 if output null
  TEST_ASSERT(tx_essence_add_output(es, OUTPUT_BASIC, NULL) == -1);

  // add basic output to the outputs list
  output_basic_t* basic_output = create_output_basic();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(es, OUTPUT_BASIC, basic_output));

  // add alias output to the output list
  output_alias_t* alias_output = create_output_alias();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(es, OUTPUT_ALIAS, alias_output));

  // add foundry output to the output list
  output_foundry_t* foundry_output = create_output_foundry();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(es, OUTPUT_FOUNDRY, foundry_output));

  // add NFT output to the output list
  output_nft_t* nft_output = create_output_nft();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(es, OUTPUT_NFT, nft_output));

  byte_t tag_data[DATA_LEN];
  iota_crypto_randombytes(tag_data, DATA_LEN);

  tagged_data_payload_t* tagged_data = tagged_data_new((byte_t*)tag_str, strlen(tag_str), tag_data, DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);

  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_payload(es, CORE_BLOCK_PAYLOAD_TAGGED, tagged_data));

  // get count of input list
  TEST_ASSERT_EQUAL_UINT16(3, utxo_inputs_count(es->inputs));

  // get count of output list
  TEST_ASSERT_EQUAL_UINT16(4, utxo_outputs_count(es->outputs));

  // Syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_essence_syntactic(es, cost));
  byte_cost_config_free(cost);

  tx_essence_print(es, 0);

  // Serialize essence and validate it
  size_t essence_buf_len = tx_essence_serialize_length(es);
  TEST_ASSERT(essence_buf_len != 0);
  byte_t* essence_buf = malloc(essence_buf_len);
  TEST_ASSERT_NOT_NULL(essence_buf);
  TEST_ASSERT(tx_essence_serialize(es, essence_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(tx_essence_serialize(es, essence_buf, essence_buf_len) == essence_buf_len);

  // Test deserialize
  transaction_essence_t* deser_es = tx_essence_deserialize(essence_buf, 1);
  TEST_ASSERT_NULL(deser_es);  // expect deserialization fails
  tx_essence_free(deser_es);
  deser_es = tx_essence_deserialize(essence_buf, essence_buf_len);
  TEST_ASSERT_NOT_NULL(deser_es);

  // check network id
  TEST_ASSERT_EQUAL_UINT16(network_id, deser_es->network_id);

  // get count of input list
  TEST_ASSERT_EQUAL_UINT16(3, utxo_inputs_count(deser_es->inputs));

  // get count of output list
  TEST_ASSERT_EQUAL_UINT16(4, utxo_outputs_count(deser_es->outputs));

  // find and validate inputs with index 1
  utxo_input_t* elm = utxo_inputs_find_by_index(deser_es->inputs, 1);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(1 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id0, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  // find and validate inputs with index 2
  elm = utxo_inputs_find_by_index(deser_es->inputs, 2);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(2 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id1, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  // find and validate inputs with index 3
  elm = utxo_inputs_find_by_index(deser_es->inputs, 3);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(3 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id2, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  // validate inputs commitment
  TEST_ASSERT_EQUAL_INT(0, memcmp(&deser_es->inputs_commitment, &inputs_commitment, CRYPTO_BLAKE2B_256_HASH_BYTES));

  // validate outputs
  // check deserialized Basic output
  utxo_output_t* output_from_deser = utxo_outputs_get(deser_es->outputs, 0);
  TEST_ASSERT_NOT_NULL(output_from_deser);
  output_basic_t* basic_from_deser = (output_basic_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(basic_output->amount, basic_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(basic_output->native_tokens),
                          native_tokens_count(basic_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(basic_output->unlock_conditions),
                          condition_list_len(basic_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(basic_output->features), feature_list_len(basic_from_deser->features));

  // check deserialized Alias output
  output_from_deser = utxo_outputs_get(deser_es->outputs, 1);
  TEST_ASSERT_EQUAL_INT(OUTPUT_ALIAS, output_from_deser->output_type);
  output_alias_t* alias_from_deser = (output_alias_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(alias_output->amount, alias_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(alias_output->native_tokens),
                          native_tokens_count(alias_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_MEMORY(alias_output->alias_id, alias_from_deser->alias_id, ALIAS_ID_BYTES);
  TEST_ASSERT_EQUAL_UINT32(alias_output->state_index, alias_from_deser->state_index);
  TEST_ASSERT_EQUAL_INT32(alias_output->state_metadata->len, alias_from_deser->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(alias_output->state_metadata->data, alias_from_deser->state_metadata->data,
                           alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_UINT32(alias_output->foundry_counter, alias_from_deser->foundry_counter);
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(alias_output->unlock_conditions),
                          condition_list_len(alias_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(alias_output->features), feature_list_len(alias_from_deser->features));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(alias_output->immutable_features),
                          feature_list_len(alias_from_deser->immutable_features));

  // check deserialized Foundry output
  output_from_deser = utxo_outputs_get(deser_es->outputs, 2);
  TEST_ASSERT_EQUAL_INT(OUTPUT_FOUNDRY, output_from_deser->output_type);
  output_foundry_t* foundry_from_deser = (output_foundry_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(foundry_output->amount, foundry_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(foundry_output->native_tokens),
                          native_tokens_count(foundry_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_INT32(foundry_output->serial, foundry_from_deser->serial);
  TEST_ASSERT_EQUAL_UINT8(foundry_output->token_scheme->type, foundry_from_deser->token_scheme->type);
  token_scheme_simple_t* simple_scheme = foundry_output->token_scheme->token_scheme;
  TEST_ASSERT_NOT_NULL(simple_scheme);
  token_scheme_simple_t* simple_scheme_deser = foundry_from_deser->token_scheme->token_scheme;
  TEST_ASSERT_NOT_NULL(simple_scheme_deser);
  TEST_ASSERT_EQUAL_MEMORY(&simple_scheme->minted_tokens, &simple_scheme_deser->minted_tokens, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_MEMORY(&simple_scheme->melted_tokens, &simple_scheme_deser->melted_tokens, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_MEMORY(&simple_scheme->max_supply, &simple_scheme_deser->max_supply, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(foundry_output->unlock_conditions),
                          condition_list_len(foundry_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(foundry_output->features), feature_list_len(foundry_from_deser->features));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(foundry_output->immutable_features),
                          feature_list_len(foundry_from_deser->immutable_features));

  // check deserialized NFT output
  output_from_deser = utxo_outputs_get(deser_es->outputs, 3);
  TEST_ASSERT_EQUAL_INT(OUTPUT_NFT, output_from_deser->output_type);
  output_nft_t* nft_from_deser = (output_nft_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(nft_output->amount, nft_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(nft_output->native_tokens),
                          native_tokens_count(nft_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_MEMORY(nft_output->nft_id, nft_from_deser->nft_id, NFT_ID_BYTES);
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(nft_output->unlock_conditions),
                          condition_list_len(nft_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(nft_output->features), feature_list_len(nft_from_deser->features));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(nft_output->immutable_features),
                          feature_list_len(nft_from_deser->immutable_features));

  // Syntactic validation
  cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_essence_syntactic(deser_es, cost));
  byte_cost_config_free(cost);

  free(essence_buf);
  output_basic_free(basic_output);
  output_alias_free(alias_output);
  output_foundry_free(foundry_output);
  output_nft_free(nft_output);
  tagged_data_free(tagged_data);
  tx_essence_free(deser_es);
  tx_essence_free(es);
}

void test_tx_payload() {
  uint16_t network_id = 2;
  transaction_payload_t* tx_payload = tx_payload_new(network_id);
  TEST_ASSERT_NOT_NULL(tx_payload);

  // get count of empty input list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(tx_payload->essence->inputs));

  // get count of empty output list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_outputs_count(tx_payload->essence->outputs));

  // Check serialize len for empty payload
  TEST_ASSERT(tx_payload_serialize_length(tx_payload) == 0);

  // print empty payload
  tx_payload_print(tx_payload, 0);

  // test for -1 if transaction id is null
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, NULL, 1) == -1);

  // add input with tx_id0
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id0, 1) == 0);

  // add input with tx_id1
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id1, 2) == 0);

  // add input with tx_id2
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id2, 3) == 0);

  // add input with tx_id3
  TEST_ASSERT(tx_essence_add_input(tx_payload->essence, 0, tx_id3, 4) == 0);

  // add inputs commitment
  TEST_ASSERT_NOT_NULL(
      memcpy(&tx_payload->essence->inputs_commitment, &inputs_commitment, CRYPTO_BLAKE2B_256_HASH_BYTES));

  // test for -1 if output null
  TEST_ASSERT(tx_essence_add_output(tx_payload->essence, OUTPUT_BASIC, NULL) == -1);

  // add basic output to the outputs list
  output_basic_t* basic_output = create_output_basic();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_BASIC, basic_output));

  // add alias output to the output list
  output_alias_t* alias_output = create_output_alias();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_ALIAS, alias_output));

  // add foundry output to the output list
  output_foundry_t* foundry_output = create_output_foundry();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_FOUNDRY, foundry_output));

  // add NFT output to the output list
  output_nft_t* nft_output = create_output_nft();
  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_output(tx_payload->essence, OUTPUT_NFT, nft_output));

  byte_t tag_data[DATA_LEN];
  iota_crypto_randombytes(tag_data, DATA_LEN);

  tagged_data_payload_t* tagged_data = tagged_data_new((byte_t*)tag_str, strlen(tag_str), tag_data, DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);

  TEST_ASSERT_EQUAL_INT(0, tx_essence_add_payload(tx_payload->essence, CORE_BLOCK_PAYLOAD_TAGGED, tagged_data));

  // add a signature unlock
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  sig[0] = 0;  // denotes ed25519 signature
  memcpy(sig + 1, test_pub_key, ED_PUBLIC_KEY_BYTES);
  memcpy(sig + (1 + ED_PUBLIC_KEY_BYTES), test_sig, ED_SIGNATURE_BYTES);
  unlock_list_add_signature(&tx_payload->unlocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(tx_payload->unlocks));

  // add a reference unlock that reference to the 0 index of unlock list.
  unlock_list_add_reference(&tx_payload->unlocks, 0);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(tx_payload->unlocks));

  // add an alias unlock that reference to the 0 index of unlock list.
  unlock_list_add_alias(&tx_payload->unlocks, 0);
  TEST_ASSERT_EQUAL_UINT16(3, unlock_list_count(tx_payload->unlocks));

  // add a NFT unlock that reference to the 0 index of unlock list.
  unlock_list_add_nft(&tx_payload->unlocks, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_list_count(tx_payload->unlocks));

  // Syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_payload_syntactic(tx_payload, cost));
  byte_cost_config_free(cost);

  // print payload
  tx_payload_print(tx_payload, 0);

  // get serialized length
  size_t payload_buf_len = tx_payload_serialize_length(tx_payload);
  TEST_ASSERT(payload_buf_len != 0);

  // Serialize payload
  byte_t* payload_buf = malloc(payload_buf_len);
  TEST_ASSERT_NOT_NULL(payload_buf);
  TEST_ASSERT(tx_payload_serialize(tx_payload, payload_buf, 1) == 0);  // expected serialization fails
  TEST_ASSERT(tx_payload_serialize(tx_payload, payload_buf, payload_buf_len) == payload_buf_len);

  // Test deserialize
  transaction_payload_t* deser_tx_payload = tx_payload_deserialize(payload_buf, 1);
  TEST_ASSERT_NULL(deser_tx_payload);  // expect deserialization fails
  tx_payload_free(deser_tx_payload);
  deser_tx_payload = tx_payload_deserialize(payload_buf, payload_buf_len);
  TEST_ASSERT_NOT_NULL(deser_tx_payload);

  // check network id
  TEST_ASSERT_EQUAL_UINT16(network_id, deser_tx_payload->essence->network_id);

  // get count of input list
  TEST_ASSERT_EQUAL_UINT16(4, utxo_inputs_count(deser_tx_payload->essence->inputs));

  // get count of output list
  TEST_ASSERT_EQUAL_UINT16(4, utxo_outputs_count(deser_tx_payload->essence->outputs));

  // find and validate inputs with index 1
  utxo_input_t* elm = utxo_inputs_find_by_index(deser_tx_payload->essence->inputs, 1);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(1 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id0, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  // find and validate inputs with index 2
  elm = utxo_inputs_find_by_index(deser_tx_payload->essence->inputs, 2);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(2 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id1, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  // find and validate inputs with index 3
  elm = utxo_inputs_find_by_index(deser_tx_payload->essence->inputs, 3);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(3 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id2, elm->tx_id, IOTA_TRANSACTION_ID_BYTES);

  // validate inputs commitment
  TEST_ASSERT_EQUAL_INT(
      0, memcmp(&deser_tx_payload->essence->inputs_commitment, &inputs_commitment, CRYPTO_BLAKE2B_256_HASH_BYTES));

  // validate outputs
  // check deserialized Basic output
  utxo_output_t* output_from_deser = utxo_outputs_get(deser_tx_payload->essence->outputs, 0);
  TEST_ASSERT_NOT_NULL(output_from_deser);
  output_basic_t* basic_from_deser = (output_basic_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(basic_output->amount, basic_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(basic_output->native_tokens),
                          native_tokens_count(basic_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(basic_output->unlock_conditions),
                          condition_list_len(basic_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(basic_output->features), feature_list_len(basic_from_deser->features));

  // check deserialized Alias output
  output_from_deser = utxo_outputs_get(deser_tx_payload->essence->outputs, 1);
  TEST_ASSERT_EQUAL_INT(OUTPUT_ALIAS, output_from_deser->output_type);
  output_alias_t* alias_from_deser = (output_alias_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(alias_output->amount, alias_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(alias_output->native_tokens),
                          native_tokens_count(alias_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_MEMORY(alias_output->alias_id, alias_from_deser->alias_id, ALIAS_ID_BYTES);
  TEST_ASSERT_EQUAL_UINT32(alias_output->state_index, alias_from_deser->state_index);
  TEST_ASSERT_EQUAL_INT32(alias_output->state_metadata->len, alias_from_deser->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(alias_output->state_metadata->data, alias_from_deser->state_metadata->data,
                           alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_UINT32(alias_output->foundry_counter, alias_from_deser->foundry_counter);
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(alias_output->unlock_conditions),
                          condition_list_len(alias_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(alias_output->features), feature_list_len(alias_from_deser->features));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(alias_output->immutable_features),
                          feature_list_len(alias_from_deser->immutable_features));

  // check deserialized Foundry output
  output_from_deser = utxo_outputs_get(deser_tx_payload->essence->outputs, 2);
  TEST_ASSERT_EQUAL_INT(OUTPUT_FOUNDRY, output_from_deser->output_type);
  output_foundry_t* foundry_from_deser = (output_foundry_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(foundry_output->amount, foundry_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(foundry_output->native_tokens),
                          native_tokens_count(foundry_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_INT32(foundry_output->serial, foundry_from_deser->serial);
  TEST_ASSERT_EQUAL_UINT8(foundry_output->token_scheme->type, foundry_from_deser->token_scheme->type);
  token_scheme_simple_t* simple_scheme = foundry_output->token_scheme->token_scheme;
  TEST_ASSERT_NOT_NULL(simple_scheme);
  token_scheme_simple_t* simple_scheme_deser = foundry_from_deser->token_scheme->token_scheme;
  TEST_ASSERT_NOT_NULL(simple_scheme_deser);
  TEST_ASSERT_EQUAL_MEMORY(&simple_scheme->minted_tokens, &simple_scheme_deser->minted_tokens, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_MEMORY(&simple_scheme->melted_tokens, &simple_scheme_deser->melted_tokens, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_MEMORY(&simple_scheme->max_supply, &simple_scheme_deser->max_supply, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(foundry_output->unlock_conditions),
                          condition_list_len(foundry_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(foundry_output->features), feature_list_len(foundry_from_deser->features));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(foundry_output->immutable_features),
                          feature_list_len(foundry_from_deser->immutable_features));

  // check deserialized NFT output
  output_from_deser = utxo_outputs_get(deser_tx_payload->essence->outputs, 3);
  TEST_ASSERT_EQUAL_INT(OUTPUT_NFT, output_from_deser->output_type);
  output_nft_t* nft_from_deser = (output_nft_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(nft_output->amount, nft_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(nft_output->native_tokens),
                          native_tokens_count(nft_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_MEMORY(nft_output->nft_id, nft_from_deser->nft_id, NFT_ID_BYTES);
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(nft_output->unlock_conditions),
                          condition_list_len(nft_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(nft_output->features), feature_list_len(nft_from_deser->features));
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(nft_output->immutable_features),
                          feature_list_len(nft_from_deser->immutable_features));

  cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(tx_payload_syntactic(deser_tx_payload, cost));
  byte_cost_config_free(cost);

  free(payload_buf);
  output_basic_free(basic_output);
  output_alias_free(alias_output);
  output_foundry_free(foundry_output);
  output_nft_free(nft_output);
  tagged_data_free(tagged_data);
  tx_payload_free(deser_tx_payload);
  tx_payload_free(tx_payload);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_tx_essence);
  RUN_TEST(test_tx_payload);

  return UNITY_END();
}
