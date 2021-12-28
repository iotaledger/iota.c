// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_extended.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_output_extended() {
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

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

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

  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

  // serialize Extended Output and validate it
  size_t output_extended_expected_len = output_extended_serialize_len(output);
  TEST_ASSERT(output_extended_expected_len != 0);
  byte_t* output_extended_buf = malloc(output_extended_expected_len);
  TEST_ASSERT_NOT_NULL(output_extended_buf);
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, output_extended_expected_len) ==
              output_extended_expected_len);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(output_extended_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_extended_deserialize(output_extended_buf, output_extended_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, deser_output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, deser_output->address->address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  token = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));

  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

  output_extended_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_extended_buf);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);
  output_extended_free(output);
  output_extended_free(deser_output);
}

void test_output_extended_without_native_tokens() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);

  // create Extended Output
  output_extended_t* output = output_extended_new(&addr, 123456789, NULL, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  TEST_ASSERT_NULL(output->native_tokens);

  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

  // serialize Extended Output and validate it
  size_t output_extended_expected_len = output_extended_serialize_len(output);
  TEST_ASSERT(output_extended_expected_len != 0);
  byte_t* output_extended_buf = malloc(output_extended_expected_len);
  TEST_ASSERT_NOT_NULL(output_extended_buf);
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, output_extended_expected_len) ==
              output_extended_expected_len);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(output_extended_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_extended_deserialize(output_extended_buf, output_extended_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, deser_output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, deser_output->address->address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  TEST_ASSERT_NULL(deser_output->native_tokens);

  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

  output_extended_print(output, 0);

  // clean up
  free(output_extended_buf);
  free_feat_blk_list(feat_blocks);
  output_extended_free(output);
  output_extended_free(deser_output);
}

void test_output_extended_without_feature_blocks() {
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

  // create Extended Output
  output_extended_t* output = output_extended_new(&addr, 123456789, native_tokens, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

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

  TEST_ASSERT_NULL(output->feature_blocks);

  // serialize Extended Output and validate it
  size_t output_extended_expected_len = output_extended_serialize_len(output);
  TEST_ASSERT(output_extended_expected_len != 0);
  byte_t* output_extended_buf = malloc(output_extended_expected_len);
  TEST_ASSERT_NOT_NULL(output_extended_buf);
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, output_extended_expected_len) ==
              output_extended_expected_len);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(output_extended_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_extended_deserialize(output_extended_buf, output_extended_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, deser_output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, deser_output->address->address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  token = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));

  TEST_ASSERT_NULL(deser_output->feature_blocks);

  output_extended_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_extended_buf);
  native_tokens_free(&native_tokens);
  output_extended_free(output);
  output_extended_free(deser_output);
}

void test_output_extended_validation() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  // create Native Tokens
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES];
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES];
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES];
  iota_crypto_randombytes(token_id1, NATIVE_TOKEN_ID_BYTES);
  iota_crypto_randombytes(token_id2, NATIVE_TOKEN_ID_BYTES);
  iota_crypto_randombytes(token_id3, NATIVE_TOKEN_ID_BYTES);
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

  //=====Test NULL address=====
  output_extended_t* output = output_extended_new(&addr, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);
  output_extended_free(output);
  output = output_extended_new(NULL, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NULL(output);

  //=====Test minimum dust allowance=====
  output = output_extended_new(&addr, 1000000, native_tokens, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);
  output_extended_free(output);
  output = output_extended_new(&addr, 999999, native_tokens, feat_blocks);
  TEST_ASSERT_NULL(output);

  //=====Test unsupported feature blocks type=====
  output = output_extended_new(&addr, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);
  output_extended_free(output);
  feat_blk_list_add_issuer(&feat_blocks, &addr);
  output = output_extended_new(&addr, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NULL(output);
  free_feat_blk_list(feat_blocks);

  //=====Test maximum feature blocks count=====
  feat_blocks = new_feat_blk_list();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);
  output = output_extended_new(&addr, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);
  output_extended_free(output);
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);
  feat_blk_list_add_sender(&feat_blocks, &addr);
  output = output_extended_new(&addr, 123456789, native_tokens, feat_blocks);
  TEST_ASSERT_NULL(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);
  output_extended_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_extended);
  RUN_TEST(test_output_extended_without_native_tokens);
  RUN_TEST(test_output_extended_without_feature_blocks);
  RUN_TEST(test_output_extended_validation);

  return UNITY_END();
}
