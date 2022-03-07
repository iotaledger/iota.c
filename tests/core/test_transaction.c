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
#include "core/models/payloads/transaction.h"
#include "core/models/unlock_block.h"

#if 0
static byte_t tx_id0[IOTA_TRANSACTION_ID_BYTES] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static byte_t tx_id1[IOTA_TRANSACTION_ID_BYTES] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                                   255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                                   255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
#endif
char const* const exp_index = "HELLO";
byte_t exp_data[12] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};

void setUp(void) {}

void tearDown(void) {}

#if 0
static output_basic_t* create_output_basic() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  // create Native Tokens
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
      0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC, 0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41, 0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A,
      0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0, 0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {
      0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E, 0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE,
      0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42, 0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {
      0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56, 0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,
      0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75, 0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
  native_tokens_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  // FIXME
  // feat_blk_list_add_ddr(&feat_blocks, 1000000);

  // create Basic Output
  output_basic_t* output = output_basic_new(&addr, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(&native_tokens);
  feat_blk_list_free(feat_blocks);

  return output;
}

static output_alias_t* create_output_alias() {
  // create Native Tokens
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
      0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56, 0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,
      0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75, 0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {
      0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC, 0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41, 0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A,
      0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0, 0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {
      0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E, 0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE,
      0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42, 0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};
  native_tokens_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create random alias ID
  byte_t alias_id[ADDRESS_ALIAS_BYTES];
  iota_crypto_randombytes(alias_id, ADDRESS_ALIAS_BYTES);

  // create random state controller address
  address_t st_ctl = {};
  st_ctl.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(st_ctl.address, ADDRESS_ED25519_BYTES);

  // create random governance controller address
  address_t gov_ctl = {};
  gov_ctl.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(gov_ctl.address, ADDRESS_ALIAS_BYTES);

  // create metadata
  byte_t test_data[] = "Test metadata...";
  byte_buf_t* metadata = byte_buf_new_with_data(test_data, sizeof(test_data));

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_sender(&feat_blocks, &st_ctl);
  feat_blk_list_add_issuer(&feat_blocks, &gov_ctl);
  feat_blk_list_add_metadata(&feat_blocks, metadata->data, metadata->len);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, &st_ctl, &gov_ctl, 123456,
                                            metadata->data, metadata->len, 654321, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  feat_blk_list_free(feat_blocks);

  return output;
}

static output_foundry_t* create_output_foundry() {
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
      0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56, 0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,
      0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75, 0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {
      0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC, 0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41, 0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A,
      0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0, 0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {
      0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E, 0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE,
      0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42, 0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};

  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  // create Native Tokens
  native_tokens_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create random token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  iota_crypto_randombytes(token_tag, TOKEN_TAG_BYTES_LEN);

  // create circulating and maximum supply
  uint256_t* circ_supply = uint256_from_str("444444444");
  uint256_t* max_supply = uint256_from_str("555555555");

  // create metadata
  byte_t test_data[] = "Test metadata...";
  byte_buf_t* metadata = byte_buf_new_with_data(test_data, sizeof(test_data));

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_metadata(&feat_blocks, metadata->data, metadata->len);

  // create Foundry Output
  output_foundry_t* output = output_foundry_new(&addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply,
                                                SIMPLE_TOKEN_SCHEME, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(circ_supply);
  free(max_supply);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  feat_blk_list_free(feat_blocks);

  return output;
}

static output_nft_t* create_output_nft() {
  // create random NFT address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, ADDRESS_NFT_BYTES);

  // create Native Tokens
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {
      0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC, 0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41, 0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A,
      0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0, 0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {
      0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56, 0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,
      0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75, 0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {
      0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E, 0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE,
      0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42, 0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};
  native_tokens_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  uint256_t* amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  uint256_t* amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  iota_crypto_randombytes(nft_id, ADDRESS_NFT_BYTES);

  // create metadata
  byte_t test_data[] = "Test metadata...";
  byte_buf_t* metadata = byte_buf_new_with_data(test_data, sizeof(test_data));

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  // FIXME
  // feat_blk_list_add_ddr(&feat_blocks, 1000000);

  // create NFT Output
  output_nft_t* output =
      output_nft_new(&addr, 123456789, native_tokens, nft_id, metadata->data, metadata->len, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  feat_blk_list_free(feat_blocks);

  return output;
}

void test_tx_essence() {
  transaction_essence_t* es = tx_essence_new();
  TEST_ASSERT_NOT_NULL(es);

  // get count of empty input list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(es->inputs));

  // get count of empty output list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_outputs_count(es->outputs));

  // Check serialize len for empty essence
  TEST_ASSERT(tx_essence_serialize_length(es) == 0);

  // print empty essence
  tx_essence_print(es);

  // test for -1 if transaction id is null
  TEST_ASSERT(tx_essence_add_input(es, 0, NULL, 1) == -1);

  // add input with tx_id0
  TEST_ASSERT(tx_essence_add_input(es, 0, tx_id0, 1) == 0);

  // add input with tx_id1
  TEST_ASSERT(tx_essence_add_input(es, 0, tx_id1, 2) == 0);

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

  // get count of input list
  TEST_ASSERT_EQUAL_UINT16(2, utxo_inputs_count(es->inputs));

  // get count of output list
  TEST_ASSERT_EQUAL_UINT16(4, utxo_outputs_count(es->outputs));

  tx_essence_print(es);

  // get serialized length
  size_t essence_buf_len = tx_essence_serialize_length(es);
  TEST_ASSERT(essence_buf_len != 0);

  // Serialize Essence
  byte_t* essence_buf = malloc(essence_buf_len);
  TEST_ASSERT_NOT_NULL(essence_buf);
  TEST_ASSERT(tx_essence_serialize(es, essence_buf, essence_buf_len) == essence_buf_len);

  // Test deserialize
  transaction_essence_t* deser_es = tx_essence_deserialize(essence_buf, essence_buf_len);

  // find and validate index
  utxo_input_t* elm = utxo_inputs_find_by_index(deser_es->inputs, 2);
  TEST_ASSERT_NOT_NULL(elm);
  TEST_ASSERT(2 == elm->output_index);
  TEST_ASSERT_EQUAL_MEMORY(tx_id1, elm->tx_id, TRANSACTION_ID_BYTES);

  free(essence_buf);
  output_basic_free(basic_output);
  output_alias_free(alias_output);
  output_foundry_free(foundry_output);
  output_nft_free(nft_output);
  tx_essence_free(deser_es);
  tx_essence_free(es);
}

void test_tx_payload() {
  transaction_payload_t* tx_payload = tx_payload_new();
  TEST_ASSERT_NOT_NULL(tx_payload);

  // get count of empty input list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_inputs_count(tx_payload->essence->inputs));

  // get count of empty output list
  TEST_ASSERT_EQUAL_UINT16(0, utxo_outputs_count(tx_payload->essence->outputs));

  // Check serialize len for empty payload
  TEST_ASSERT(tx_payload_serialize_length(tx_payload) == 0);

  // print empty payload
  tx_payload_print(tx_payload);

  // add input with tx_id0
  TEST_ASSERT(tx_payload_add_input(tx_payload, 0, tx_id0, 1) == 0);

  // add input with tx_id1
  TEST_ASSERT(tx_payload_add_input(tx_payload, 0, tx_id1, 2) == 0);

  // add basic output to the outputs list
  output_basic_t* basic_output = create_output_basic();
  TEST_ASSERT_EQUAL_INT(0, tx_payload_add_output(tx_payload, OUTPUT_BASIC, basic_output));

  // add alias output to the output list
  output_alias_t* alias_output = create_output_alias();
  TEST_ASSERT_EQUAL_INT(0, tx_payload_add_output(tx_payload, OUTPUT_ALIAS, alias_output));

  // add foundry output to the output list
  output_foundry_t* foundry_output = create_output_foundry();
  TEST_ASSERT_EQUAL_INT(0, tx_payload_add_output(tx_payload, OUTPUT_FOUNDRY, foundry_output));

  // add NFT output to the output list
  output_nft_t* nft_output = create_output_nft();
  TEST_ASSERT_EQUAL_INT(0, tx_payload_add_output(tx_payload, OUTPUT_NFT, nft_output));

  // add unlock blocks
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  TEST_ASSERT_EQUAL_INT(0, tx_payload_add_sig_block(tx_payload, sig, ED25519_SIGNATURE_BLOCK_BYTES));
  // To Do - Add Reference, Alias and NFT Unlock Block test cases

  // print payload
  tx_payload_print(tx_payload);

  // get serialized length
  size_t payload_buf_len = tx_payload_serialize_length(tx_payload);
  TEST_ASSERT(payload_buf_len != 0);

  // Serialize payload
  byte_t* payload_buf = malloc(payload_buf_len);
  TEST_ASSERT_NOT_NULL(payload_buf);
  TEST_ASSERT(tx_payload_serialize(tx_payload, payload_buf, payload_buf_len) == payload_buf_len);

  // To Do - Deserialize tx_payload

  free(payload_buf);
  output_basic_free(basic_output);
  output_alias_free(alias_output);
  output_foundry_free(foundry_output);
  output_nft_free(nft_output);
  //  tx_payload_free(deser_tx_payload);
  tx_payload_free(tx_payload);
}
#endif

int main() {
  UNITY_BEGIN();

  printf("FIXME, borken because of output refactoring\n");
  // RUN_TEST(test_tx_essence);
  // RUN_TEST(test_tx_payload);

  return UNITY_END();
}
