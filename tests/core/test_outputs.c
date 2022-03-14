// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/outputs.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56,
                                           0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,  0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75,
                                           0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC,  0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41,
                                           0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A, 0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0,
                                           0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E,
                                           0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE, 0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42,
                                           0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};
byte_t test_meta[] = "Test metadata...";
byte_t test_immut_meta[] = "Test immutable metadata...";

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

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ED25519_PUBKEY_BYTES);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta),
                                            654321, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  native_tokens_free(native_tokens);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);

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

  // create circulating and maximum supply
  uint256_t* circ_supply = uint256_from_str("444444444");
  uint256_t* max_supply = uint256_from_str("555555555");

  // create random Alias address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(addr.address, ALIAS_ID_BYTES);

  // create random token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  iota_crypto_randombytes(token_tag, TOKEN_TAG_BYTES_LEN);

  // create Foundry Output
  output_foundry_t* output =
      output_foundry_new(&addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply, SIMPLE_TOKEN_SCHEME,
                         test_meta, sizeof(test_meta), test_immut_meta, sizeof(test_immut_meta));

  free(amount1);
  free(amount2);
  free(amount3);
  free(circ_supply);
  free(max_supply);
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
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  unlock_cond_blk_t* unlock_addr = cond_blk_addr_new(&addr);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  cond_blk_free(unlock_addr);

  // create random sender address
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ED25519_PUBKEY_BYTES);
  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ED25519_PUBKEY_BYTES);
  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &sender_addr) == 0);
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);
  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create NFT Output
  output_nft_t* output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(native_tokens);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);

  return output;
}

void test_utxo_outputs() {
  utxo_outputs_list_t* outputs = utxo_outputs_new();
  TEST_ASSERT_NULL(outputs);

  // print out an empty list
  utxo_outputs_print(outputs, 0);

  // add basic output to the outputs list
  output_basic_t* basic_output = create_output_basic();
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_add(&outputs, OUTPUT_BASIC, basic_output));

  // add alias output to the output list
  output_alias_t* alias_output = create_output_alias();
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_add(&outputs, OUTPUT_ALIAS, alias_output));

  // add foundry output to the output list
  output_foundry_t* foundry_output = create_output_foundry();
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_add(&outputs, OUTPUT_FOUNDRY, foundry_output));

  // add NFT output to the output list
  output_nft_t* nft_output = create_output_nft();
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_add(&outputs, OUTPUT_NFT, nft_output));

  // check outputs list length
  TEST_ASSERT_EQUAL_INT(4, utxo_outputs_count(outputs));

  // Syntactic validation
  byte_cost_config_t* cost = byte_cost_config_default_new();
  TEST_ASSERT_TRUE(utxo_outputs_syntactic(outputs, cost));
  byte_cost_config_free(cost);

  // serialize outputs list and validate it
  size_t expected_serialized_len = utxo_outputs_serialize_len(outputs);
  TEST_ASSERT(expected_serialized_len != 0);
  byte_t* outputs_list_buf = malloc(expected_serialized_len);
  TEST_ASSERT_NOT_NULL(outputs_list_buf);
  TEST_ASSERT(utxo_outputs_serialize(outputs, outputs_list_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(utxo_outputs_serialize(outputs, outputs_list_buf, expected_serialized_len) == expected_serialized_len);

  // deserialize outputs list and validate it
  utxo_outputs_list_t* deser_outputs = utxo_outputs_deserialize(outputs_list_buf, 1);
  TEST_ASSERT_NULL(deser_outputs);  // expect deserialization fails
  deser_outputs = utxo_outputs_deserialize(outputs_list_buf, expected_serialized_len);
  TEST_ASSERT_NOT_NULL(deser_outputs);
  TEST_ASSERT_EQUAL_INT(4, utxo_outputs_count(deser_outputs));

  // check deserialized Basic output
  utxo_output_t* output_from_deser = utxo_outputs_get(deser_outputs, 0);
  TEST_ASSERT_NOT_NULL(output_from_deser);
  output_basic_t* basic_from_deser = (output_basic_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(basic_output->amount, basic_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(basic_output->native_tokens),
                          native_tokens_count(basic_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_UINT8(cond_blk_list_len(basic_output->unlock_conditions),
                          cond_blk_list_len(basic_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(basic_output->feature_blocks),
                          feat_blk_list_len(basic_from_deser->feature_blocks));

  // check deserialized Alias output
  output_from_deser = utxo_outputs_get(outputs, 1);
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
  TEST_ASSERT_EQUAL_UINT8(cond_blk_list_len(alias_output->unlock_conditions),
                          cond_blk_list_len(alias_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(alias_output->feature_blocks),
                          feat_blk_list_len(alias_from_deser->feature_blocks));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(alias_output->immutable_blocks),
                          feat_blk_list_len(alias_from_deser->immutable_blocks));

  // check deserialized Foundry output
  output_from_deser = utxo_outputs_get(outputs, 2);
  TEST_ASSERT_EQUAL_INT(OUTPUT_FOUNDRY, output_from_deser->output_type);
  output_foundry_t* foundry_from_deser = (output_foundry_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(foundry_output->amount, foundry_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(foundry_output->native_tokens),
                          native_tokens_count(foundry_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_INT32(foundry_output->serial, foundry_from_deser->serial);
  TEST_ASSERT_EQUAL_MEMORY(foundry_output->token_tag, foundry_from_deser->token_tag, TOKEN_TAG_BYTES_LEN);
  TEST_ASSERT_EQUAL_MEMORY(&foundry_output->circ_supply, &foundry_from_deser->circ_supply, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_MEMORY(&foundry_output->max_supply, &foundry_from_deser->max_supply, sizeof(uint256_t));
  TEST_ASSERT_EQUAL_UINT8(foundry_output->token_scheme, foundry_from_deser->token_scheme);
  TEST_ASSERT_EQUAL_UINT8(cond_blk_list_len(foundry_output->unlock_conditions),
                          cond_blk_list_len(foundry_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(foundry_output->feature_blocks),
                          feat_blk_list_len(foundry_from_deser->feature_blocks));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(foundry_output->immutable_blocks),
                          feat_blk_list_len(foundry_from_deser->immutable_blocks));

  // check deserialized NFT output
  output_from_deser = utxo_outputs_get(outputs, 3);
  TEST_ASSERT_EQUAL_INT(OUTPUT_NFT, output_from_deser->output_type);
  output_nft_t* nft_from_deser = (output_nft_t*)output_from_deser->output;
  TEST_ASSERT_EQUAL_UINT64(nft_output->amount, nft_from_deser->amount);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(nft_output->native_tokens),
                          native_tokens_count(nft_from_deser->native_tokens));
  TEST_ASSERT_EQUAL_MEMORY(nft_output->nft_id, nft_from_deser->nft_id, NFT_ID_BYTES);
  TEST_ASSERT_EQUAL_UINT8(cond_blk_list_len(nft_output->unlock_conditions),
                          cond_blk_list_len(nft_from_deser->unlock_conditions));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(nft_output->feature_blocks),
                          feat_blk_list_len(nft_from_deser->feature_blocks));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(nft_output->immutable_blocks),
                          feat_blk_list_len(nft_from_deser->immutable_blocks));

  // print out outputs list
  utxo_outputs_print(outputs, 0);

  // clean up
  output_basic_free(basic_output);
  output_alias_free(alias_output);
  output_foundry_free(foundry_output);
  output_nft_free(nft_output);
  free(outputs_list_buf);
  utxo_outputs_free(outputs);
  utxo_outputs_free(deser_outputs);
}

void test_deprecated_and_unsupported_utxo_outputs() {
  utxo_outputs_list_t* outputs = utxo_outputs_new();
  TEST_ASSERT_NULL(outputs);

  uint8_t dummy_output = 0;

  // try to add SigLockedSingleOutput to the outputs list
  TEST_ASSERT_EQUAL_INT(-1, utxo_outputs_add(&outputs, OUTPUT_SINGLE_OUTPUT, &dummy_output));

  // try to add SigLockedDustAllowanceOutput to the output list
  TEST_ASSERT_EQUAL_INT(-1, utxo_outputs_add(&outputs, OUTPUT_DUST_ALLOWANCE, &dummy_output));

  // try to add Treasury output to the output list
  TEST_ASSERT_EQUAL_INT(-1, utxo_outputs_add(&outputs, OUTPUT_TREASURY, &dummy_output));

  // check outputs list length
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_count(outputs));

  // create test data for deserialization
  byte_t outputs_list_contains_SigLockedSingleOutput_buf[] = {
      1, 0,                 // number of outputs
      OUTPUT_SINGLE_OUTPUT  // SigLockedSingleOutput output type
  };
  // try to deserialize outputs list and validate it
  utxo_outputs_list_t* deser_outputs = utxo_outputs_deserialize(
      outputs_list_contains_SigLockedSingleOutput_buf, sizeof(outputs_list_contains_SigLockedSingleOutput_buf));
  TEST_ASSERT_NULL(deser_outputs);  // expect deserialization fails

  // create test data for deserialization
  byte_t outputs_list_contains_SigLockedDustAllowanceOutput_buf[] = {
      1, 0,                  // number of outputs
      OUTPUT_DUST_ALLOWANCE  // SigLockedSingleOutput output type
  };
  // try to deserialize outputs list and validate it
  deser_outputs = utxo_outputs_deserialize(outputs_list_contains_SigLockedDustAllowanceOutput_buf,
                                           sizeof(outputs_list_contains_SigLockedDustAllowanceOutput_buf));
  TEST_ASSERT_NULL(deser_outputs);  // expect deserialization fails

  // create test data for deserialization
  byte_t outputs_list_contains_TreasuryOutput_buf[] = {
      1, 0,            // number of outputs
      OUTPUT_TREASURY  // Treasury output type
  };
  // try to deserialize outputs list and validate it
  deser_outputs = utxo_outputs_deserialize(outputs_list_contains_TreasuryOutput_buf,
                                           sizeof(outputs_list_contains_TreasuryOutput_buf));
  TEST_ASSERT_NULL(deser_outputs);  // expect deserialization fails
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_utxo_outputs);
  RUN_TEST(test_deprecated_and_unsupported_utxo_outputs);

  return UNITY_END();
}
