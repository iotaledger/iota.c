// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/output_extended.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/outputs.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

static output_extended_t* create_output_extended() {
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
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);

  // create Extended Output
  output_extended_t* output = output_extended_new(&addr, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);

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
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
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
  free_feat_blk_list(feat_blocks);

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
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);

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
  free_feat_blk_list(feat_blocks);

  return output;
}

void setUp(void) {}

void tearDown(void) {}

void test_utxo_outputs() {
  utxo_outputs_list_t* outputs = utxo_outputs_new();
  TEST_ASSERT_NULL(outputs);

  // print out an empty list
  utxo_outputs_print(outputs);

  // add extended output to the outputs list
  output_extended_t* extended_output = create_output_extended();
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_add(&outputs, OUTPUT_EXTENDED, extended_output));

  // add alias output to the output list
  output_alias_t* alias_output = create_output_alias();
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_add(&outputs, OUTPUT_ALIAS, alias_output));

  // add NFT output to the output list
  output_nft_t* nft_output = create_output_nft();
  TEST_ASSERT_EQUAL_INT(0, utxo_outputs_add(&outputs, OUTPUT_NFT, nft_output));

  // check outputs list length
  TEST_ASSERT_EQUAL_INT(3, utxo_outputs_count(outputs));

  // check extended output
  utxo_output_t* output_from_list = utxo_outputs_get(outputs, 0);
  TEST_ASSERT_EQUAL_INT(OUTPUT_EXTENDED, output_from_list->output_type);
  output_extended_t* extended_output_from_list = (output_extended_t*)output_from_list->output;
  TEST_ASSERT_EQUAL_UINT8(extended_output->address->type, extended_output_from_list->address->type);
  TEST_ASSERT_EQUAL_MEMORY(extended_output->address->address, extended_output_from_list->address->address,
                           ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(extended_output->amount, extended_output_from_list->amount);
  TEST_ASSERT_EQUAL_UINT16(native_tokens_count(&extended_output->native_tokens),
                           native_tokens_count(&extended_output_from_list->native_tokens));
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(extended_output->feature_blocks),
                          feat_blk_list_len(extended_output_from_list->feature_blocks));

  // check alias output
  output_from_list = utxo_outputs_get(outputs, 1);
  TEST_ASSERT_EQUAL_INT(OUTPUT_ALIAS, output_from_list->output_type);
  output_alias_t* alias_output_from_list = (output_alias_t*)output_from_list->output;
  TEST_ASSERT_EQUAL_UINT64(alias_output->amount, alias_output_from_list->amount);
  TEST_ASSERT_EQUAL_UINT16(native_tokens_count(&alias_output->native_tokens),
                           native_tokens_count(&alias_output_from_list->native_tokens));
  TEST_ASSERT_EQUAL_MEMORY(alias_output->alias_id, alias_output_from_list->alias_id, ADDRESS_ALIAS_BYTES);
  TEST_ASSERT_EQUAL_UINT8(alias_output->st_ctl->type, alias_output_from_list->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(alias_output->st_ctl->address, alias_output_from_list->st_ctl->address,
                           ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT8(alias_output->gov_ctl->type, alias_output_from_list->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(alias_output->gov_ctl->address, alias_output_from_list->gov_ctl->address,
                           ADDRESS_ALIAS_BYTES);
  TEST_ASSERT_EQUAL_UINT32(alias_output->state_index, alias_output_from_list->state_index);
  TEST_ASSERT_EQUAL_INT32(alias_output->state_metadata->len, alias_output_from_list->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(alias_output->state_metadata->data, alias_output_from_list->state_metadata->data,
                           alias_output->state_metadata->len);
  TEST_ASSERT_EQUAL_UINT32(alias_output->foundry_counter, alias_output_from_list->foundry_counter);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(alias_output->feature_blocks),
                          feat_blk_list_len(alias_output_from_list->feature_blocks));

  // check NFT output
  output_from_list = utxo_outputs_get(outputs, 2);
  TEST_ASSERT_EQUAL_INT(OUTPUT_NFT, output_from_list->output_type);
  output_nft_t* nft_output_from_list = (output_nft_t*)output_from_list->output;
  TEST_ASSERT_EQUAL_UINT8(nft_output->address->type, nft_output_from_list->address->type);
  TEST_ASSERT_EQUAL_MEMORY(nft_output->address->address, nft_output_from_list->address->address, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_UINT64(nft_output->amount, nft_output_from_list->amount);
  TEST_ASSERT_EQUAL_UINT16(native_tokens_count(&nft_output->native_tokens),
                           native_tokens_count(&nft_output_from_list->native_tokens));
  TEST_ASSERT_EQUAL_MEMORY(nft_output->nft_id, nft_output_from_list->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_INT32(nft_output->immutable_metadata->len, nft_output_from_list->immutable_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(nft_output->immutable_metadata->data, nft_output_from_list->immutable_metadata->data,
                           nft_output->immutable_metadata->len);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(nft_output->feature_blocks),
                          feat_blk_list_len(nft_output_from_list->feature_blocks));

  // serialize outputs list and validate it
  size_t expected_serialized_len = utxo_outputs_serialize_len(outputs);
  TEST_ASSERT(expected_serialized_len != 0);
  byte_t* outputs_list_buf = malloc(expected_serialized_len);
  TEST_ASSERT_NOT_NULL(outputs_list_buf);
  TEST_ASSERT(utxo_outputs_serialize(outputs, outputs_list_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(utxo_outputs_serialize(outputs, outputs_list_buf, expected_serialized_len) == expected_serialized_len);

  // print out outputs list
  utxo_outputs_print(outputs);

  // clean up
  free(extended_output);
  free(outputs_list_buf);
  utxo_outputs_free(outputs);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_utxo_outputs);

  return UNITY_END();
}
