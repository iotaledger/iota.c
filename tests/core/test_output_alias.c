// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_alias.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

// test Native Token IDs
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

void test_output_alias() {
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

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
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
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta),
                                            654321, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);
  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&output->native_tokens));
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
  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);
  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof(test_meta), output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, output->state_metadata->data, output->state_metadata->len);
  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate unlock condition blocks
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 2);
  // state controller address should equal to stat_block object
  unlock_cond_blk_t* exp_state = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  unlock_cond_blk_t* exp_gov = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // immutable feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->immutable_blocks));

  // 0: Metadata
  feat_block_t* immut_feat_block = feat_blk_list_get(output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);
  // 1: Issuer
  immut_feat_block = feat_blk_list_get(output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));

  // serialize alias Output and validate it
  size_t output_serialzed_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_serialzed_len != 0);
  byte_t* output_serialized_buf = malloc(output_serialzed_len);
  TEST_ASSERT_NOT_NULL(output_serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_serialized_buf, output_serialzed_len - 1) == 0);
  TEST_ASSERT(output_alias_serialize(output, output_serialized_buf, output_serialzed_len) == output_serialzed_len);

  // deserialize alias Output and validate it
  // expect deserialization fails
  TEST_ASSERT_NULL(output_alias_deserialize(output_serialized_buf, output_serialzed_len - 1));
  output_alias_t* deser_output = output_alias_deserialize(output_serialized_buf, output_serialzed_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);
  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(&output->native_tokens),
                          native_tokens_count(&deser_output->native_tokens));
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

  // deserialized alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);
  // deserialized state index
  TEST_ASSERT_EQUAL_UINT32(output->state_index, deser_output->state_index);
  // deserialized metadata
  TEST_ASSERT_EQUAL_INT32(output->state_metadata->len, deser_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(output->state_metadata->data, deser_output->state_metadata->data,
                           deser_output->state_metadata->len);
  // deserialized foundry index
  TEST_ASSERT_EQUAL_UINT32(output->foundry_counter, deser_output->foundry_counter);

  // deserialized unlock condition blocks
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == cond_blk_list_len(output->unlock_conditions));
  // state controller address should equal to stat_block object
  exp_state = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  exp_gov = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // deserialized immutable feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->immutable_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(deser_output->immutable_blocks));
  // 0: Issuer
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));
  // 1: Metadata
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);

  // print alias output
  output_alias_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  free(output_serialized_buf);
  native_tokens_free(&native_tokens);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
}

void test_output_alias_without_native_tokens() {
  // create random alias ID
  byte_t alias_id[ADDRESS_ALIAS_BYTES];
  iota_crypto_randombytes(alias_id, ADDRESS_ALIAS_BYTES);

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* gov_block = cond_blk_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_block);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, gov_block) == 0);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta));

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, NULL, alias_id, 123456, test_meta, sizeof(test_meta), 654321,
                                            unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);
  // validate native tokens
  TEST_ASSERT_NULL(output->native_tokens);
  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, output->alias_id, ADDRESS_ALIAS_BYTES);
  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);
  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof(test_meta), output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, output->state_metadata->data, output->state_metadata->len);

  // validate foundry index
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);
  // validate unlock condition blocks
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 2);
  // state controller address should equal to stat_block object
  unlock_cond_blk_t* exp_state = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  unlock_cond_blk_t* exp_gov = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // immutable feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->immutable_blocks));

  // 0: Metadata
  feat_block_t* immut_feat_block = feat_blk_list_get(output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);
  // 1: Issuer
  immut_feat_block = feat_blk_list_get(output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));

  // serialize alias Output and validate it
  size_t output_serialzed_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_serialzed_len != 0);
  byte_t* output_serialized_buf = malloc(output_serialzed_len);
  TEST_ASSERT_NOT_NULL(output_serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_serialized_buf, output_serialzed_len - 1) == 0);
  TEST_ASSERT(output_alias_serialize(output, output_serialized_buf, output_serialzed_len) == output_serialzed_len);

  // deserialize alias Output and validate it
  // expect deserialization fails
  TEST_ASSERT_NULL(output_alias_deserialize(output_serialized_buf, output_serialzed_len - 1));
  output_alias_t* deser_output = output_alias_deserialize(output_serialized_buf, output_serialzed_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);
  // deserialized native tokens
  TEST_ASSERT_NULL(deser_output->native_tokens);
  // deserialized alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);
  // deserialized state index
  TEST_ASSERT_EQUAL_UINT32(output->state_index, deser_output->state_index);
  // deserialized metadata
  TEST_ASSERT_EQUAL_INT32(output->state_metadata->len, deser_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(output->state_metadata->data, deser_output->state_metadata->data,
                           deser_output->state_metadata->len);
  // deserialized foundry index
  TEST_ASSERT_EQUAL_UINT32(output->foundry_counter, deser_output->foundry_counter);

  // deserialized unlock condition blocks
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == cond_blk_list_len(output->unlock_conditions));
  // state controller address should equal to stat_block object
  exp_state = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  exp_gov = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // deserialized immutable feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->immutable_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(deser_output->immutable_blocks));
  // 0: Issuer
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));
  // 1: Metadata
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);

  // print alias output
  output_alias_print(output, 0);

  // clean up
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  free(output_serialized_buf);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
}

void test_output_alias_without_metadata() {
  // create Native Tokens
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

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* gov_block = cond_blk_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_block);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, gov_block) == 0);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta));

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, NULL, 0, 654321, unlock_conds,
                                            feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);
  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&output->native_tokens));
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
  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);
  // validate metadata
  TEST_ASSERT_NULL(output->state_metadata);
  // validate foundry index
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate unlock condition blocks
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 2);
  // state controller address should equal to stat_block object
  unlock_cond_blk_t* exp_state = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  unlock_cond_blk_t* exp_gov = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // immutable feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->immutable_blocks));

  // 0: Metadata
  feat_block_t* immut_feat_block = feat_blk_list_get(output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);
  // 1: Issuer
  immut_feat_block = feat_blk_list_get(output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));

  // validate alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, output->alias_id, ADDRESS_ALIAS_BYTES);

  // serialize alias Output and validate it
  size_t output_alias_expected_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_alias_expected_len != 0);
  byte_t* output_alias_buf = malloc(output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(output_alias_buf);
  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len - 1) == 0);
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len) == output_alias_expected_len);

  // deserialize alias Output and validate it
  output_alias_t* deser_output = output_alias_deserialize(output_alias_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_alias_deserialize(output_alias_buf, output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&deser_output->native_tokens));
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

  // deserialized alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);
  // deserialized state index
  TEST_ASSERT_EQUAL_UINT32(123456, deser_output->state_index);
  // deserialized metadata
  TEST_ASSERT_NULL(deser_output->state_metadata);
  // deserialized foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, deser_output->foundry_counter);

  // deserialized unlock condition blocks
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == cond_blk_list_len(output->unlock_conditions));
  // state controller address should equal to stat_block object
  exp_state = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  exp_gov = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // deserialized immutable feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->immutable_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(deser_output->immutable_blocks));
  // 0: Issuer
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));
  // 1: Metadata
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);

  // print alias output
  output_alias_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(&native_tokens);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
  free(output_alias_buf);
}

void test_output_alias_without_feature_blocks() {
  // create Native Tokens
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

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* gov_block = cond_blk_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_block);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, gov_block) == 0);

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);
  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, NULL, 0, 654321, unlock_conds,
                                            NULL, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&output->native_tokens));
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
  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);
  // validate metadata
  TEST_ASSERT_NULL(output->state_metadata);
  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate unlock condition blocks
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 2);
  // state controller address should equal to stat_block object
  unlock_cond_blk_t* exp_state = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  unlock_cond_blk_t* exp_gov = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // validate feature blocks
  TEST_ASSERT_NULL(output->feature_blocks);

  // immutable feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->immutable_blocks));

  // 0: Metadata
  feat_block_t* immut_feat_block = feat_blk_list_get(output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);
  // 1: Issuer
  immut_feat_block = feat_blk_list_get(output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));

  // serialize alias Output and validate it
  size_t output_alias_expected_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_alias_expected_len != 0);
  byte_t* output_alias_buf = malloc(output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(output_alias_buf);
  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len - 1) == 0);
  TEST_ASSERT(output_alias_serialize(output, output_alias_buf, output_alias_expected_len) == output_alias_expected_len);

  // deserialize alias Output and validate it
  output_alias_t* deser_output = output_alias_deserialize(output_alias_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_alias_deserialize(output_alias_buf, output_alias_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  // deserialized tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&deser_output->native_tokens));
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

  // deserialized alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);
  // deserialized state index
  TEST_ASSERT_EQUAL_UINT32(123456, deser_output->state_index);
  // deserialized metadata
  TEST_ASSERT_NULL(deser_output->state_metadata);
  // deserialized foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, deser_output->foundry_counter);

  // deserialized unlock condition blocks
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == cond_blk_list_len(output->unlock_conditions));
  // state controller address should equal to stat_block object
  exp_state = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  exp_gov = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // deserialized feature blocks
  TEST_ASSERT_NULL(deser_output->feature_blocks);

  // deserialized immutable feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->immutable_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(deser_output->immutable_blocks));
  // 0: Issuer
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_ISSUER_BLOCK, immut_feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&issuer_addr, (address_t*)immut_feat_block->block));
  // 1: Metadata
  immut_feat_block = feat_blk_list_get(deser_output->immutable_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, immut_feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_immut_meta, ((feat_metadata_blk_t*)immut_feat_block->block)->data,
                           ((feat_metadata_blk_t*)immut_feat_block->block)->data_len);

  // print alias output
  output_alias_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_alias_buf);
  native_tokens_free(&native_tokens);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(immut_feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
}

void test_output_alias_without_immutable_feature_blocks() {
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

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* gov_block = cond_blk_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_block);

  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, gov_block) == 0);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta),
                                            654321, unlock_conds, feat_blocks, NULL);
  TEST_ASSERT_NOT_NULL(output);
  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&output->native_tokens));
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
  // validate state index
  TEST_ASSERT_EQUAL_UINT32(123456, output->state_index);
  // validate metadata
  TEST_ASSERT_EQUAL_INT32(sizeof(test_meta), output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, output->state_metadata->data, output->state_metadata->len);
  // validate foundry counter
  TEST_ASSERT_EQUAL_UINT32(654321, output->foundry_counter);

  // validate unlock condition blocks
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(output->unlock_conditions) == 2);
  // state controller address should equal to stat_block object
  unlock_cond_blk_t* exp_state = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  unlock_cond_blk_t* exp_gov = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // immutable feature blocks should be in adding order
  TEST_ASSERT_NULL(output->immutable_blocks);

  // serialize alias Output and validate it
  size_t output_serialzed_len = output_alias_serialize_len(output);
  TEST_ASSERT(output_serialzed_len != 0);
  byte_t* output_serialized_buf = malloc(output_serialzed_len);
  TEST_ASSERT_NOT_NULL(output_serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_alias_serialize(output, output_serialized_buf, output_serialzed_len - 1) == 0);
  TEST_ASSERT(output_alias_serialize(output, output_serialized_buf, output_serialzed_len) == output_serialzed_len);

  // deserialize alias Output and validate it
  // expect deserialization fails
  TEST_ASSERT_NULL(output_alias_deserialize(output_serialized_buf, output_serialzed_len - 1));
  output_alias_t* deser_output = output_alias_deserialize(output_serialized_buf, output_serialzed_len);
  TEST_ASSERT_NOT_NULL(deser_output);

  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);
  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(&output->native_tokens),
                          native_tokens_count(&deser_output->native_tokens));
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

  // deserialized alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, deser_output->alias_id, ADDRESS_ALIAS_BYTES);
  // deserialized state index
  TEST_ASSERT_EQUAL_UINT32(output->state_index, deser_output->state_index);
  // deserialized metadata
  TEST_ASSERT_EQUAL_INT32(output->state_metadata->len, deser_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(output->state_metadata->data, deser_output->state_metadata->data,
                           deser_output->state_metadata->len);
  // deserialized foundry index
  TEST_ASSERT_EQUAL_UINT32(output->foundry_counter, deser_output->foundry_counter);

  // deserialized unlock condition blocks
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(deser_output->unlock_conditions) == cond_blk_list_len(output->unlock_conditions));
  // state controller address should equal to stat_block object
  exp_state = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  exp_gov = cond_blk_list_get_type(deser_output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // print alias output
  output_alias_print(output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  free(output_serialized_buf);
  native_tokens_free(&native_tokens);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  output_alias_free(output);
  output_alias_free(deser_output);
}

void test_output_alias_clone() {
  //=====NULL Alias Output object=====
  output_alias_t* new_output = output_alias_clone(NULL);
  TEST_ASSERT_NULL(new_output);

  //=====Test Alias Output object=====
  // create Native Tokens
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

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* gov_block = cond_blk_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_block);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, gov_block) == 0);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta));

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);
  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create alias Output
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta),
                                            654321, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // clone Alias Output object
  new_output = output_alias_clone(output);
  TEST_ASSERT_NOT_NULL(new_output);

  // compare amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, new_output->amount);
  // compare native tokens
  TEST_ASSERT_NOT_NULL(new_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(&output->native_tokens), native_tokens_count(&new_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  native_tokens_t* token = new_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));

  // compare alias ID
  TEST_ASSERT_EQUAL_MEMORY(alias_id, new_output->alias_id, ADDRESS_ALIAS_BYTES);
  // compare state index
  TEST_ASSERT_EQUAL_UINT32(output->state_index, new_output->state_index);
  // compare metadata
  TEST_ASSERT_EQUAL_INT32(output->state_metadata->len, new_output->state_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(output->state_metadata->data, new_output->state_metadata->data,
                           new_output->state_metadata->len);
  // compare foundry index
  TEST_ASSERT_EQUAL_UINT32(output->foundry_counter, new_output->foundry_counter);

  // compare unlock condition blocks
  TEST_ASSERT_NOT_NULL(new_output->unlock_conditions);
  // should be 2 condition blocks
  TEST_ASSERT(cond_blk_list_len(new_output->unlock_conditions) == cond_blk_list_len(output->unlock_conditions));
  // state controller address should equal to stat_block object
  unlock_cond_blk_t* exp_state = cond_blk_list_get_type(new_output->unlock_conditions, UNLOCK_COND_STATE);
  TEST_ASSERT(state_block->type == exp_state->type);
  TEST_ASSERT(address_equal((address_t*)state_block->block, (address_t*)exp_state->block));
  // governor address should equal to gov_block object
  unlock_cond_blk_t* exp_gov = cond_blk_list_get_type(new_output->unlock_conditions, UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(gov_block->type == exp_gov->type);
  TEST_ASSERT(address_equal((address_t*)gov_block->block, (address_t*)exp_gov->block));

  // compare feature blocks
  TEST_ASSERT_NOT_NULL(new_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(new_output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(new_output->feature_blocks, 0);
  TEST_ASSERT_NOT_NULL(feat_block);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT32(sizeof(test_meta), ((feat_metadata_blk_t*)feat_block->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // compare immutable feature blocks
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_NOT_NULL(new_output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(output->immutable_blocks), feat_blk_list_len(new_output->immutable_blocks));

  // print new Alias Output
  output_alias_print(new_output, 0);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(&native_tokens);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_alias_free(new_output);
  output_alias_free(output);
}

void test_output_alias_condition_blocks() {
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

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // empty unlock condition
  TEST_ASSERT_NULL(output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta), 654321,
                                    NULL, feat_blocks, immut_feat_blocks));

  // unlock conditions for testing
  // UNLOCK_COND_STATE
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  // UNLOCK_COND_GOVERNOR
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* gov_block = cond_blk_governor_new(&test_addr);
  TEST_ASSERT_NOT_NULL(gov_block);
  // UNLOCK_COND_ADDRESS
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* addr_block = cond_blk_addr_new(&test_addr);
  TEST_ASSERT_NOT_NULL(addr_block);
  // UNLOCK_COND_STORAGE
  unlock_cond_blk_t* storage_block = cond_blk_storage_new(&test_addr, 100000000);
  TEST_ASSERT_NOT_NULL(storage_block);

  // invalid - unlock condition count must be 2
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT_NULL(output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta), 654321,
                                    unlock_conds, feat_blocks, immut_feat_blocks));

  // invalid - unlock condition count must be UNLOCK_COND_STATE and UNLOCK_COND_GOVERNOR
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, addr_block) == 0);
  TEST_ASSERT_NULL(output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta), 654321,
                                    unlock_conds, feat_blocks, immut_feat_blocks));

  // unlock condition with UNLOCK_COND_ADDRESS and UNLOCK_COND_STORAGE
  cond_blk_list_free(unlock_conds);
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, addr_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, storage_block) == 0);
  TEST_ASSERT_NULL(output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta), 654321,
                                    unlock_conds, feat_blocks, immut_feat_blocks));

  // unlock condition with UNLOCK_COND_STATE and UNLOCK_COND_STORAGE
  cond_blk_list_free(unlock_conds);
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, storage_block) == 0);
  TEST_ASSERT_NULL(output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta), 654321,
                                    unlock_conds, feat_blocks, immut_feat_blocks));

  // unlock condition with UNLOCK_COND_STATE, UNLOCK_COND_GOVERNOR, and UNLOCK_COND_STORAGE
  cond_blk_list_free(unlock_conds);
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, state_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, gov_block) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, storage_block) == 0);
  TEST_ASSERT_NULL(output_alias_new(123456789, native_tokens, alias_id, 123456, test_meta, sizeof(test_meta), 654321,
                                    unlock_conds, feat_blocks, immut_feat_blocks));

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(&native_tokens);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  cond_blk_free(addr_block);
  cond_blk_free(storage_block);
  cond_blk_list_free(unlock_conds);
}

void test_output_alias_state_metadata_length() {
  native_tokens_t* native_tokens = native_tokens_new();
  uint256_t* amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);

  // create random alias ID
  byte_t alias_id[ADDRESS_ALIAS_BYTES];
  iota_crypto_randombytes(alias_id, ADDRESS_ALIAS_BYTES);

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  // random state controller address
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
  unlock_cond_blk_t* state_block = cond_blk_state_new(&test_addr);
  TEST_ASSERT_NOT_NULL(state_block);
  iota_crypto_randombytes(test_addr.address, ADDRESS_ALIAS_BYTES);
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
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create state metadata
  byte_t meta_data[MAX_METADATA_LENGTH_BYTES] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));

  // create alias output with maximum state metadata length
  output_alias_t* output = output_alias_new(123456789, native_tokens, alias_id, 123456, meta_data, sizeof(meta_data),
                                            654321, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);
  output_alias_free(output);

  // create alias output with too big state metadata
  output = output_alias_new(123456789, native_tokens, alias_id, 123456, meta_data, sizeof(meta_data) + 1, 654321,
                            unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NULL(output);

  // clean up
  free(amount1);
  cond_blk_free(state_block);
  cond_blk_free(gov_block);
  native_tokens_free(&native_tokens);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_alias_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_alias);
  RUN_TEST(test_output_alias_without_native_tokens);
  RUN_TEST(test_output_alias_without_metadata);
  RUN_TEST(test_output_alias_without_feature_blocks);
  RUN_TEST(test_output_alias_without_immutable_feature_blocks);
  RUN_TEST(test_output_alias_clone);
  RUN_TEST(test_output_alias_condition_blocks);
  RUN_TEST(test_output_alias_state_metadata_length);

  return UNITY_END();
}
