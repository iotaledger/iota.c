// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_foundry.h"
#include "core/utils/byte_buffer.h"
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

native_tokens_list_t* native_tokens = NULL;
uint256_t* amount1 = NULL;
uint256_t* amount2 = NULL;
uint256_t* amount3 = NULL;
uint256_t* circ_supply = NULL;
uint256_t* max_supply = NULL;

void setUp(void) {
  // create Native Tokens
  native_tokens = native_tokens_new();
  amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);
  // create circulating and maximum supply
  circ_supply = uint256_from_str("444444444");
  max_supply = uint256_from_str("555555555");
}

void tearDown(void) {
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(native_tokens);
  free(circ_supply);
  free(max_supply);
}

void test_output_foundry() {
  // create random Alias address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(addr.address, ADDRESS_ALIAS_BYTES);

  // create random token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  iota_crypto_randombytes(token_tag, TOKEN_TAG_BYTES_LEN);

  // create Foundry Output
  output_foundry_t* output =
      output_foundry_new(&addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply, SIMPLE_TOKEN_SCHEME,
                         test_meta, sizeof(test_meta), test_immut_meta, sizeof(test_immut_meta));
  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(output->native_tokens));
  native_tokens_list_t* tokens = output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, tokens->token->amount, sizeof(uint256_t));

  // validate serial number
  TEST_ASSERT(output->serial == 22);
  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, output->token_tag, TOKEN_TAG_BYTES_LEN);
  // validate circulating supply
  TEST_ASSERT(uint256_equal(circ_supply, &output->circ_supply) == 0);
  // validate maximum supply
  TEST_ASSERT(uint256_equal(max_supply, &output->max_supply) == 0);
  // validate token scheme
  TEST_ASSERT(output->token_scheme == SIMPLE_TOKEN_SCHEME);

  // validate unlock condition
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 1);
  unlock_cond_blk_t* expect_unlock_addr = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(expect_unlock_addr);
  TEST_ASSERT(address_equal(&addr, (address_t*)expect_unlock_addr->block));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // validate immutable feature blocks
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->immutable_blocks));
  feat_block_t* immut_feat_block = feat_blk_list_get(output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_immut_meta), ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);

  // serialize foundry Output and validate it
  size_t output_foundry_expected_len = output_foundry_serialize_len(output);
  TEST_ASSERT(output_foundry_expected_len != 0);
  byte_t* output_foundry_buf = malloc(output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(output_foundry_buf);
  // expect serialization fails
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len - 1) == 0);
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len) ==
              output_foundry_expected_len);

  // deserialize foundry Output and validate it
  output_foundry_t* deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  tokens = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, tokens->token->amount, sizeof(uint256_t));

  // deserialized serial number
  TEST_ASSERT_EQUAL_UINT32(22, deser_output->serial);
  // deserialized token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, deser_output->token_tag, TOKEN_TAG_BYTES_LEN);
  // deserialized circulating supply
  TEST_ASSERT(uint256_equal(circ_supply, &deser_output->circ_supply) == 0);
  // deserialized maximum supply
  TEST_ASSERT(uint256_equal(max_supply, &deser_output->max_supply) == 0);

  // deserialized unlock condition
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == 1);
  expect_unlock_addr = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(expect_unlock_addr);
  TEST_ASSERT(address_equal(&addr, (address_t*)expect_unlock_addr->block));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print foundry output
  output_foundry_print(output, 0);

  // clean up
  free(output_foundry_buf);
  output_foundry_free(output);
  output_foundry_free(deser_output);
}

void test_output_foundry_without_native_tokens() {
  // create random Alias address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(addr.address, ADDRESS_ALIAS_BYTES);

  // create random token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  iota_crypto_randombytes(token_tag, TOKEN_TAG_BYTES_LEN);

  // create Foundry Output
  output_foundry_t* output = output_foundry_new(&addr, 123456789, NULL, 22, token_tag, circ_supply, max_supply,
                                                SIMPLE_TOKEN_SCHEME, test_meta, sizeof(test_meta), NULL, 0);
  // validation
  TEST_ASSERT_NOT_NULL(output);
  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);
  // validate native tokens
  TEST_ASSERT_NULL(output->native_tokens);

  // validate serial number
  TEST_ASSERT(output->serial == 22);
  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, output->token_tag, TOKEN_TAG_BYTES_LEN);
  // validate circulating supply
  TEST_ASSERT(uint256_equal(circ_supply, &output->circ_supply) == 0);
  // validate maximum supply
  TEST_ASSERT(uint256_equal(max_supply, &output->max_supply) == 0);
  // validate token scheme
  TEST_ASSERT(output->token_scheme == SIMPLE_TOKEN_SCHEME);

  // validate unlock condition
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 1);
  unlock_cond_blk_t* expect_unlock_addr = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(expect_unlock_addr);
  TEST_ASSERT(address_equal(&addr, (address_t*)expect_unlock_addr->block));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // validate immutable feature blocks
  TEST_ASSERT_NULL(output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(output->immutable_blocks));

  // serialize foundry Output and validate it
  size_t output_foundry_expected_len = output_foundry_serialize_len(output);
  TEST_ASSERT(output_foundry_expected_len != 0);
  byte_t* output_foundry_buf = malloc(output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(output_foundry_buf);
  // expect serialization fails
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len - 1) == 0);
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len) ==
              output_foundry_expected_len);

  // deserialize foundry Output and validate it
  output_foundry_t* deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  // deserialized native tokens
  TEST_ASSERT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(0, native_tokens_count(deser_output->native_tokens));

  // deserialized serial number
  TEST_ASSERT_EQUAL_UINT32(22, deser_output->serial);
  // deserialized token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, deser_output->token_tag, TOKEN_TAG_BYTES_LEN);
  // deserialized circulating supply
  TEST_ASSERT(uint256_equal(circ_supply, &deser_output->circ_supply) == 0);
  // deserialized maximum supply
  TEST_ASSERT(uint256_equal(max_supply, &deser_output->max_supply) == 0);

  // deserialized unlock condition
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == 1);
  expect_unlock_addr = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(expect_unlock_addr);
  TEST_ASSERT(address_equal(&addr, (address_t*)expect_unlock_addr->block));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print foundry output
  output_foundry_print(output, 0);

  // clean up
  free(output_foundry_buf);
  output_foundry_free(output);
  output_foundry_free(deser_output);
}

void test_output_foundry_without_metadata() {
  // create random Alias address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(addr.address, ADDRESS_ALIAS_BYTES);

  // create random token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  iota_crypto_randombytes(token_tag, TOKEN_TAG_BYTES_LEN);

  // create Foundry Output
  output_foundry_t* output = output_foundry_new(&addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply,
                                                SIMPLE_TOKEN_SCHEME, NULL, 0, NULL, 0);
  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(output->native_tokens));
  native_tokens_list_t* tokens = output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, tokens->token->amount, sizeof(uint256_t));

  // validate serial number
  TEST_ASSERT(output->serial == 22);
  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, output->token_tag, TOKEN_TAG_BYTES_LEN);
  // validate circulating supply
  TEST_ASSERT(uint256_equal(circ_supply, &output->circ_supply) == 0);
  // validate maximum supply
  TEST_ASSERT(uint256_equal(max_supply, &output->max_supply) == 0);
  // validate token scheme
  TEST_ASSERT(output->token_scheme == SIMPLE_TOKEN_SCHEME);

  // validate unlock condition
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 1);
  unlock_cond_blk_t* expect_unlock_addr = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(expect_unlock_addr);
  TEST_ASSERT(address_equal(&addr, (address_t*)expect_unlock_addr->block));

  // validate feature blocks
  TEST_ASSERT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(output->feature_blocks));

  // validate immutable feature blocks
  TEST_ASSERT_NULL(output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(output->immutable_blocks));

  // serialize foundry Output and validate it
  size_t output_foundry_expected_len = output_foundry_serialize_len(output);
  TEST_ASSERT(output_foundry_expected_len != 0);
  byte_t* output_foundry_buf = malloc(output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(output_foundry_buf);
  // expect serialization fails
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len - 1) == 0);
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len) ==
              output_foundry_expected_len);

  // deserialize foundry Output and validate it
  output_foundry_t* deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  tokens = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, tokens->token->amount, sizeof(uint256_t));

  // deserialized serial number
  TEST_ASSERT_EQUAL_UINT32(22, deser_output->serial);
  // deserialized token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, deser_output->token_tag, TOKEN_TAG_BYTES_LEN);
  // deserialized circulating supply
  TEST_ASSERT(uint256_equal(circ_supply, &deser_output->circ_supply) == 0);
  // deserialized maximum supply
  TEST_ASSERT(uint256_equal(max_supply, &deser_output->max_supply) == 0);

  // deserialized unlock condition
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == 1);
  expect_unlock_addr = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_ADDRESS);
  TEST_ASSERT_NOT_NULL(expect_unlock_addr);
  TEST_ASSERT(address_equal(&addr, (address_t*)expect_unlock_addr->block));

  // deserialized feature blocks
  TEST_ASSERT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(deser_output->feature_blocks));

  // print foundry output
  output_foundry_print(output, 0);

  // clean up
  free(output_foundry_buf);
  output_foundry_free(output);
  output_foundry_free(deser_output);
}

void test_output_foundry_syntactic() {
  // create random ED25519 address
  address_t ed_addr = {};
  ed_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(ed_addr.address, ADDRESS_ED25519_BYTES);

  // create random Alias address
  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(alias_addr.address, ADDRESS_ALIAS_BYTES);

  // create random NFT address
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(nft_addr.address, ADDRESS_NFT_BYTES);

  // create random token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  iota_crypto_randombytes(token_tag, TOKEN_TAG_BYTES_LEN);

  // invalid address type, must be alias address
  TEST_ASSERT_NULL(output_foundry_new(&ed_addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply,
                                      SIMPLE_TOKEN_SCHEME, test_meta, sizeof(test_meta), NULL, 0));
  TEST_ASSERT_NULL(output_foundry_new(&nft_addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply,
                                      SIMPLE_TOKEN_SCHEME, test_meta, sizeof(test_meta), NULL, 0));
  // invalid meta data
  TEST_ASSERT_NULL(output_foundry_new(&alias_addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply,
                                      SIMPLE_TOKEN_SCHEME, test_meta, MAX_METADATA_LENGTH_BYTES + 1, NULL, 0));

  // invalid circulating and maximun supply
  TEST_ASSERT_NULL(output_foundry_new(&alias_addr, 123456789, native_tokens, 22, token_tag, NULL, max_supply,
                                      SIMPLE_TOKEN_SCHEME, test_meta, sizeof(test_meta), NULL, 0));
  TEST_ASSERT_NULL(output_foundry_new(&alias_addr, 123456789, native_tokens, 22, token_tag, circ_supply, NULL,
                                      SIMPLE_TOKEN_SCHEME, test_meta, sizeof(test_meta), NULL, 0));
  TEST_ASSERT_NULL(output_foundry_new(&alias_addr, 123456789, native_tokens, 22, token_tag, NULL, NULL,
                                      SIMPLE_TOKEN_SCHEME, test_meta, sizeof(test_meta), NULL, 0));

  // valid address and metadata
  output_foundry_t* output = output_foundry_new(&alias_addr, 123456789, native_tokens, 22, token_tag, circ_supply,
                                                max_supply, SIMPLE_TOKEN_SCHEME, test_meta, sizeof(test_meta), NULL, 0);
  TEST_ASSERT_NOT_NULL(output);
  output_foundry_free(output);
  output = output_foundry_new(&alias_addr, 123456789, NULL, 22, token_tag, circ_supply, max_supply, SIMPLE_TOKEN_SCHEME,
                              test_meta, sizeof(test_meta), NULL, 0);
  TEST_ASSERT_NOT_NULL(output);
  output_foundry_free(output);
}

void test_output_foundry_clone() {
  //=====NULL Foundry Output object=====
  output_foundry_t* new_output = output_foundry_clone(NULL);
  TEST_ASSERT_NULL(new_output);

  //=====Test Foundry Output object=====
  // create random Alias address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(addr.address, ADDRESS_ALIAS_BYTES);

  // create random token tag
  byte_t token_tag[TOKEN_TAG_BYTES_LEN];
  iota_crypto_randombytes(token_tag, TOKEN_TAG_BYTES_LEN);

  // create Foundry Output
  output_foundry_t* output =
      output_foundry_new(&addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply, SIMPLE_TOKEN_SCHEME,
                         test_meta, sizeof(test_meta), test_immut_meta, sizeof(test_immut_meta));
  TEST_ASSERT_NOT_NULL(output);

  // clone Foundry Output object
  new_output = output_foundry_clone(output);

  // validate new Foundry Output object
  // validate amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, new_output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_NOT_NULL(new_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(output->native_tokens), native_tokens_count(new_output->native_tokens));

  // validate serial number
  TEST_ASSERT_EQUAL_UINT32(output->serial, new_output->serial);

  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(output->token_tag, new_output->token_tag, TOKEN_TAG_BYTES_LEN);

  // validate circulating supply
  TEST_ASSERT_EQUAL_MEMORY(&output->circ_supply, &new_output->circ_supply, sizeof(uint256_t));

  // validate maximum supply
  TEST_ASSERT_EQUAL_MEMORY(&output->max_supply, &new_output->max_supply, sizeof(uint256_t));

  // validate token scheme
  TEST_ASSERT(output->token_scheme == new_output->token_scheme);

  // validate unlock condition blocks
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_NOT_NULL(new_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(cond_blk_list_len(output->unlock_conditions),
                          cond_blk_list_len(new_output->unlock_conditions));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_NOT_NULL(new_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(output->feature_blocks), feat_blk_list_len(new_output->feature_blocks));

  // validate immutable feature blocks
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_NOT_NULL(new_output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(output->immutable_blocks), feat_blk_list_len(new_output->immutable_blocks));

  // print new foundry output
  output_foundry_print(output, 0);

  // clean up
  output_foundry_free(new_output);
  output_foundry_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_foundry);
  RUN_TEST(test_output_foundry_without_native_tokens);
  RUN_TEST(test_output_foundry_without_metadata);
  RUN_TEST(test_output_foundry_syntactic);
  RUN_TEST(test_output_foundry_clone);

  return UNITY_END();
}
