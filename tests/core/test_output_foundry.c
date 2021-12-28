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

void setUp(void) {}

void tearDown(void) {}

void test_output_foundry() {
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
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_metadata(&feat_blocks, metadata->data, metadata->len);

  // create Foundry Output
  output_foundry_t* output = output_foundry_new(&addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply,
                                                SIMPLE_TOKEN_SCHEME, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&output->native_tokens));
  native_tokens_t* token = output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));

  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, output->token_tag, TOKEN_TAG_BYTES_LEN);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // serialize foundry Output and validate it
  size_t output_foundry_expected_len = output_foundry_serialize_len(output);
  TEST_ASSERT(output_foundry_expected_len != 0);
  byte_t* output_foundry_buf = malloc(output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(output_foundry_buf);
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len) ==
              output_foundry_expected_len);

  // deserialize foundry Output and validate it
  output_foundry_t* deser_output = output_foundry_deserialize(output_foundry_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // validation
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);

  // validate address
  TEST_ASSERT_EQUAL_MEMORY(addr.address, deser_output->address->address, ADDRESS_ED25519_BYTES);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validate native tokens
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  token = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));

  // validate serial number
  TEST_ASSERT_EQUAL_UINT32(22, deser_output->serial);

  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, deser_output->token_tag, TOKEN_TAG_BYTES_LEN);

  // validate circulating supply
  TEST_ASSERT(!uint256_equal(circ_supply, deser_output->circ_supply));

  // validate maximum supply
  TEST_ASSERT(!uint256_equal(max_supply, deser_output->max_supply));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print foundry output
  output_foundry_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(circ_supply);
  free(max_supply);
  free(output_foundry_buf);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);
  output_foundry_free(output);
  output_foundry_free(deser_output);
}

void test_output_foundry_without_native_tokens() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

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
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_metadata(&feat_blocks, metadata->data, metadata->len);

  // create Foundry Output
  output_foundry_t* output = output_foundry_new(&addr, 123456789, NULL, 22, token_tag, circ_supply, max_supply,
                                                SIMPLE_TOKEN_SCHEME, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, output->token_tag, TOKEN_TAG_BYTES_LEN);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // serialize foundry Output and validate it
  size_t output_foundry_expected_len = output_foundry_serialize_len(output);
  TEST_ASSERT(output_foundry_expected_len != 0);
  byte_t* output_foundry_buf = malloc(output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(output_foundry_buf);
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len) ==
              output_foundry_expected_len);

  // deserialize foundry Output and validate it
  output_foundry_t* deser_output = output_foundry_deserialize(output_foundry_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // validate address
  TEST_ASSERT_EQUAL_MEMORY(addr.address, deser_output->address->address, ADDRESS_ED25519_BYTES);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validate serial number
  TEST_ASSERT_EQUAL_UINT32(22, deser_output->serial);

  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, deser_output->token_tag, TOKEN_TAG_BYTES_LEN);

  // validate circulating supply
  TEST_ASSERT(!uint256_equal(circ_supply, deser_output->circ_supply));

  // validate maximum supply
  TEST_ASSERT(!uint256_equal(max_supply, deser_output->max_supply));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print foundry output
  output_foundry_print(output, 0);

  // clean up
  free(circ_supply);
  free(max_supply);
  free(output_foundry_buf);
  byte_buf_free(metadata);
  free_feat_blk_list(feat_blocks);
  output_foundry_free(output);
  output_foundry_free(deser_output);
}

void test_output_foundry_without_feature_blocks() {
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

  // create Foundry Output
  output_foundry_t* output = output_foundry_new(&addr, 123456789, native_tokens, 22, token_tag, circ_supply, max_supply,
                                                SIMPLE_TOKEN_SCHEME, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&output->native_tokens));
  native_tokens_t* token = output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));

  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, output->token_tag, TOKEN_TAG_BYTES_LEN);

  // serialize foundry Output and validate it
  size_t output_foundry_expected_len = output_foundry_serialize_len(output);
  TEST_ASSERT(output_foundry_expected_len != 0);
  byte_t* output_foundry_buf = malloc(output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(output_foundry_buf);
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_foundry_serialize(output, output_foundry_buf, output_foundry_expected_len) ==
              output_foundry_expected_len);

  // deserialize foundry Output and validate it
  output_foundry_t* deser_output = output_foundry_deserialize(output_foundry_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_foundry_deserialize(output_foundry_buf, output_foundry_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // validation
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);

  // validate address
  TEST_ASSERT_EQUAL_MEMORY(addr.address, deser_output->address->address, ADDRESS_ED25519_BYTES);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validate native tokens
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  token = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));

  // validate serial number
  TEST_ASSERT_EQUAL_UINT32(22, deser_output->serial);

  // validate token tag
  TEST_ASSERT_EQUAL_MEMORY(token_tag, deser_output->token_tag, TOKEN_TAG_BYTES_LEN);

  // validate circulating supply
  TEST_ASSERT(!uint256_equal(circ_supply, deser_output->circ_supply));

  // validate maximum supply
  TEST_ASSERT(!uint256_equal(max_supply, deser_output->max_supply));

  // print foundry output
  output_foundry_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(circ_supply);
  free(max_supply);
  free(output_foundry_buf);
  native_tokens_free(&native_tokens);
  output_foundry_free(output);
  output_foundry_free(deser_output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_foundry);
  RUN_TEST(test_output_foundry_without_native_tokens);
  RUN_TEST(test_output_foundry_without_feature_blocks);

  return UNITY_END();
}
