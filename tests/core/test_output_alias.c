// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_alias.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_output_alias() {
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

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);

  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", output->state_metadata->data, output->state_metadata->len);

  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&st_ctl, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&gov_ctl, *(&feat_block->block), ADDRESS_ALIAS_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // serialize alias Output and validate it
  size_t output_alias_expected_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_alias_expected_len != 0);
  byte_t* output_alias_buf = malloc(output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(output_alias_buf);
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len) == output_alias_expected_len);

  // deserialize alias Output and validate it
  output_alias_t* deser_output = output_alias_deserialize(output_alias_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_alias_deserialize(output_alias_buf, output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validation
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
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

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, deser_output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, deser_output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, deser_output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, deser_output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, deser_output->state_index);

  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), deser_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", deser_output->state_metadata->data, deser_output->state_metadata->len);

  // validate foundry index
  TEST_ASSERT_EQUAL_UINT32(654321, deser_output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&st_ctl, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&gov_ctl, *(&feat_block->block), ADDRESS_ALIAS_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print alias output
  output_alias_print(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_alias_buf);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
}

void test_output_alias_without_native_tokens() {
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
  output_alias_t* output = output_alias_new(123456789, NULL, alias_id, &st_ctl, &gov_ctl, 123456, metadata->data,
                                            metadata->len, 654321, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NULL(output->native_tokens);

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);

  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", output->state_metadata->data, output->state_metadata->len);

  // validate foundry index
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&st_ctl, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&gov_ctl, *(&feat_block->block), ADDRESS_ALIAS_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // serialize alias Output and validate it
  size_t output_alias_expected_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_alias_expected_len != 0);
  byte_t* output_alias_buf = malloc(output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(output_alias_buf);
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len) == output_alias_expected_len);

  // deserialize alias Output and validate it
  output_alias_t* deser_output = output_alias_deserialize(output_alias_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_alias_deserialize(output_alias_buf, output_alias_expected_len);

  // validation
  TEST_ASSERT_NOT_NULL(deser_output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validate native tokens
  TEST_ASSERT_NULL(deser_output->native_tokens);

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, deser_output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, deser_output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, deser_output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, deser_output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, deser_output->state_index);

  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), deser_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", deser_output->state_metadata->data, deser_output->state_metadata->len);

  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, deser_output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&st_ctl, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&gov_ctl, *(&feat_block->block), ADDRESS_ALIAS_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print alias output
  output_alias_print(output);

  // clean up
  free(output_alias_buf);
  byte_buf_free(metadata);
  free_feat_blk_list(feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
}

void test_output_alias_without_metadata() {
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
  output_alias_t* output =
      output_alias_new(123456789, native_tokens, alias_id, &st_ctl, &gov_ctl, 123456, NULL, 0, 654321, feat_blocks);

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

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);

  // validate metadata
  TEST_ASSERT_NULL(output->state_metadata);

  // validate foundry output
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&st_ctl, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&gov_ctl, *(&feat_block->block), ADDRESS_ALIAS_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // serialize alias Output and validate it
  size_t output_alias_expected_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_alias_expected_len != 0);
  byte_t* output_alias_buf = malloc(output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(output_alias_buf);
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len) == output_alias_expected_len);

  // deserialize alias Output and validate it
  output_alias_t* deser_output = output_alias_deserialize(output_alias_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_alias_deserialize(output_alias_buf, output_alias_expected_len);

  // validation
  TEST_ASSERT_NOT_NULL(deser_output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
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

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, deser_output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, deser_output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, deser_output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, deser_output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, deser_output->state_index);

  // validate metadata
  TEST_ASSERT_NULL(deser_output->state_metadata);

  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, deser_output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&st_ctl, *(&feat_block->block), ADDRESS_ED25519_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&gov_ctl, *(&feat_block->block), ADDRESS_ALIAS_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof("Test metadata..."), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print alias output
  output_alias_print(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_alias_buf);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
}

void test_output_alias_without_feature_blocks() {
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

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, &st_ctl, &gov_ctl, 123456,
                                            metadata->data, metadata->len, 654321, NULL);

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

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);

  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", output->state_metadata->data, output->state_metadata->len);

  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NULL(output->feature_blocks);

  // serialize alias Output and validate it
  size_t output_alias_expected_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_alias_expected_len != 0);
  byte_t* output_alias_buf = malloc(output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(output_alias_buf);
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len) == output_alias_expected_len);

  // deserialize alias Output and validate it
  output_alias_t* deser_output = output_alias_deserialize(output_alias_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_alias_deserialize(output_alias_buf, output_alias_expected_len);

  // validation
  TEST_ASSERT_NOT_NULL(deser_output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
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

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);

  // validate state controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, deser_output->st_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(st_ctl.address, deser_output->st_ctl->address, ADDRESS_ED25519_BYTES);

  // validate governance controller
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ALIAS, deser_output->gov_ctl->type);
  TEST_ASSERT_EQUAL_MEMORY(gov_ctl.address, deser_output->gov_ctl->address, ADDRESS_ALIAS_BYTES);

  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, deser_output->state_index);

  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), deser_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", deser_output->state_metadata->data, deser_output->state_metadata->len);

  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, deser_output->foundry_counter);

  // validate feature blocks
  TEST_ASSERT_NULL(deser_output->feature_blocks);

  // print alias output
  output_alias_print(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_alias_buf);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  output_alias_free(output);
  output_alias_free(deser_output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_alias);
  RUN_TEST(test_output_alias_without_native_tokens);
  RUN_TEST(test_output_alias_without_metadata);
  RUN_TEST(test_output_alias_without_feature_blocks);

  return UNITY_END();
}
