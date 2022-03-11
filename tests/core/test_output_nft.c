// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_nft.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

// global test sets
byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E,
                                           0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE, 0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42,
                                           0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};
byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC,  0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41,
                                           0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A, 0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0,
                                           0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xEF, 0x56,
                                           0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,  0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75,
                                           0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};
byte_t test_meta[] = "Test metadata...";
byte_t test_immut_meta[] = "Test immutable metadata...";
byte_t test_tag[] = "Test TAG";
native_tokens_list_t* native_tokens = NULL;
uint256_t* amount1 = NULL;
uint256_t* amount2 = NULL;
uint256_t* amount3 = NULL;

unlock_cond_blk_t* unlock_addr = NULL;
unlock_cond_blk_t* unlock_storage = NULL;
address_t test_addr = {};
uint64_t unlock_storage_amount = 9876543210;
unlock_cond_blk_t* unlock_timelock = NULL;
uint32_t unlock_time_ms = 1200;
uint32_t unlock_time_unix = 164330008;
unlock_cond_blk_t* unlock_expir = NULL;
unlock_cond_blk_t* unlock_state = NULL;
unlock_cond_blk_t* unlock_gov = NULL;

void setUp(void) {
  // example native token list
  native_tokens = native_tokens_new();
  amount1 = uint256_from_str("111111111");
  native_tokens_add(&native_tokens, token_id1, amount1);
  amount2 = uint256_from_str("222222222");
  native_tokens_add(&native_tokens, token_id2, amount2);
  amount3 = uint256_from_str("333333333");
  native_tokens_add(&native_tokens, token_id3, amount3);

  // create random ED25519 address
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);
  // create test unlock conditions
  unlock_addr = cond_blk_addr_new(&test_addr);
  unlock_storage = cond_blk_storage_new(&test_addr, unlock_storage_amount);
  unlock_timelock = cond_blk_timelock_new(unlock_time_ms, unlock_time_unix);
  unlock_expir = cond_blk_expir_new(&test_addr, unlock_time_ms, unlock_time_unix);
  unlock_state = cond_blk_state_new(&test_addr);
  unlock_gov = cond_blk_governor_new(&test_addr);
}

void tearDown(void) {
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(native_tokens);
  cond_blk_free(unlock_addr);
  cond_blk_free(unlock_storage);
  cond_blk_free(unlock_timelock);
  cond_blk_free(unlock_expir);
  cond_blk_free(unlock_state);
  cond_blk_free(unlock_gov);
}

void test_output_nft() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  // create random sender address
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ADDRESS_ED25519_BYTES);
  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);
  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_tag(&feat_blocks, test_tag, sizeof(test_tag)) == 0);
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &sender_addr) == 0);
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);
  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  iota_crypto_randombytes(nft_id, ADDRESS_NFT_BYTES);

  // create NFT Output
  output_nft_t* output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(output->native_tokens));
  native_tokens_list_t* tokens = output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, &tokens->token->amount, sizeof(uint256_t));

  // validate NFT ID
  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Storage Return Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond_block->block)->amount);
  // 2: Expiration Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_expir_t*)cond_block->block)->addr));
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_expir_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_expir_t*)cond_block->block)->time);
  // 3: Timelock Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond_block->type);
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_timelock_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_timelock_t*)cond_block->block)->time);

  // feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(output->feature_blocks));

  // 0: Tag
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feat_tag_blk_t*)feat_block->block)->tag,
                           ((feat_tag_blk_t*)feat_block->block)->tag_len);
  // 1: Sender
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&sender_addr, (address_t*)feat_block->block));
  // 2: Metadata
  feat_block = feat_blk_list_get(output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
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

  // serialize NFT Output and validate it
  size_t output_nft_expected_len = output_nft_serialize_len(output);
  TEST_ASSERT(output_nft_expected_len != 0);
  byte_t* output_nft_buf = malloc(output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(output_nft_buf);
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, output_nft_expected_len) == output_nft_expected_len);

  // deserialize NFT Output and validate it
  output_nft_t* deser_output = output_nft_deserialize(output_nft_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_nft_deserialize(output_nft_buf, output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);

  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  tokens = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, &tokens->token->amount, sizeof(uint256_t));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(deser_output->feature_blocks));
  // 0: Sender
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&sender_addr, (address_t*)feat_block->block));
  // 1: Metadata
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);
  // 2: Tag
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feat_tag_blk_t*)feat_block->block)->tag,
                           ((feat_tag_blk_t*)feat_block->block)->tag_len);

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

  output_nft_print(output, 0);

  free(output_nft_buf);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_nft_free(deser_output);
  output_nft_free(output);
}

void test_output_nft_without_native_tokens() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  // create random sender address
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ADDRESS_ED25519_BYTES);
  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);
  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_tag(&feat_blocks, test_tag, sizeof(test_tag)) == 0);
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &sender_addr) == 0);
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);
  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  iota_crypto_randombytes(nft_id, ADDRESS_NFT_BYTES);

  // create NFT Output
  output_nft_t* output = output_nft_new(123456789, NULL, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NULL(output->native_tokens);

  // validate NFT ID
  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Storage Return Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond_block->block)->amount);
  // 2: Expiration Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_expir_t*)cond_block->block)->addr));
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_expir_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_expir_t*)cond_block->block)->time);
  // 3: Timelock Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond_block->type);
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_timelock_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_timelock_t*)cond_block->block)->time);

  // feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(output->feature_blocks));

  // 0: Tag
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feat_tag_blk_t*)feat_block->block)->tag,
                           ((feat_tag_blk_t*)feat_block->block)->tag_len);
  // 1: Sender
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&sender_addr, (address_t*)feat_block->block));
  // 2: Metadata
  feat_block = feat_blk_list_get(output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
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

  // serialize NFT Output and validate it
  size_t output_nft_expected_len = output_nft_serialize_len(output);
  TEST_ASSERT(output_nft_expected_len != 0);
  byte_t* output_nft_buf = malloc(output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(output_nft_buf);
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, output_nft_expected_len) == output_nft_expected_len);

  // deserialize NFT Output and validate it
  output_nft_t* deser_output = output_nft_deserialize(output_nft_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_nft_deserialize(output_nft_buf, output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);

  TEST_ASSERT_NULL(deser_output->native_tokens);

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(deser_output->feature_blocks));
  // 0: Sender
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&sender_addr, (address_t*)feat_block->block));
  // 1: Metadata
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);
  // 2: Tag
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feat_tag_blk_t*)feat_block->block)->tag,
                           ((feat_tag_blk_t*)feat_block->block)->tag_len);

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

  free(output_nft_buf);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_nft_free(deser_output);
  output_nft_free(output);
}

void test_output_nft_without_feature_blocks() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  iota_crypto_randombytes(nft_id, ADDRESS_NFT_BYTES);

  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);
  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create NFT Output
  output_nft_t* output = output_nft_new(123456789, NULL, nft_id, unlock_conds, NULL, immut_feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NULL(output->native_tokens);

  // validate NFT ID
  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Storage Return Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond_block->block)->amount);
  // 2: Expiration Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_expir_t*)cond_block->block)->addr));
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_expir_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_expir_t*)cond_block->block)->time);
  // 3: Timelock Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond_block->type);
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_timelock_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_timelock_t*)cond_block->block)->time);

  // no feature blocks
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

  // serialize NFT Output and validate it
  size_t output_nft_expected_len = output_nft_serialize_len(output);
  TEST_ASSERT(output_nft_expected_len != 0);
  byte_t* output_nft_buf = malloc(output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(output_nft_buf);
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, output_nft_expected_len) == output_nft_expected_len);

  // deserialize NFT Output and validate it
  output_nft_t* deser_output = output_nft_deserialize(output_nft_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_nft_deserialize(output_nft_buf, output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);

  TEST_ASSERT_NULL(deser_output->native_tokens);

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

  free(output_nft_buf);
  cond_blk_list_free(unlock_conds);
  output_nft_free(deser_output);
  feat_blk_list_free(immut_feat_blocks);
  output_nft_free(output);
}

void test_output_nft_without_immutable_feature_blocks() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  // create random sender address
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ADDRESS_ED25519_BYTES);
  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_tag(&feat_blocks, test_tag, sizeof(test_tag)) == 0);
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &sender_addr) == 0);
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  iota_crypto_randombytes(nft_id, ADDRESS_NFT_BYTES);

  // create NFT Output
  output_nft_t* output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);

  // validate amount
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(output->native_tokens));
  native_tokens_list_t* tokens = output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, &tokens->token->amount, sizeof(uint256_t));

  // validate NFT ID
  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Storage Return Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond_block->block)->amount);
  // 2: Expiration Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_expir_t*)cond_block->block)->addr));
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_expir_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_expir_t*)cond_block->block)->time);
  // 3: Timelock Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond_block->type);
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_timelock_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_timelock_t*)cond_block->block)->time);

  // feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(output->feature_blocks));

  // 0: Tag
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feat_tag_blk_t*)feat_block->block)->tag,
                           ((feat_tag_blk_t*)feat_block->block)->tag_len);
  // 1: Sender
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&sender_addr, (address_t*)feat_block->block));
  // 2: Metadata
  feat_block = feat_blk_list_get(output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // no immutable feature blocks
  TEST_ASSERT_NULL(output->immutable_blocks);

  // serialize NFT Output and validate it
  size_t output_nft_expected_len = output_nft_serialize_len(output);
  TEST_ASSERT(output_nft_expected_len != 0);
  byte_t* output_nft_buf = malloc(output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(output_nft_buf);
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(output_nft_serialize(output, output_nft_buf, output_nft_expected_len) == output_nft_expected_len);

  // deserialize NFT Output and validate it
  output_nft_t* deser_output = output_nft_deserialize(output_nft_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_nft_deserialize(output_nft_buf, output_nft_expected_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);

  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  tokens = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, &tokens->token->amount, sizeof(uint256_t));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(deser_output->feature_blocks));
  // 0: Sender
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&sender_addr, (address_t*)feat_block->block));
  // 1: Metadata
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);
  // 2: Tag
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feat_tag_blk_t*)feat_block->block)->tag,
                           ((feat_tag_blk_t*)feat_block->block)->tag_len);

  // no immutable feature blocks
  TEST_ASSERT_NULL(deser_output->immutable_blocks);

  output_nft_print(output, 0);

  free(output_nft_buf);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  output_nft_free(deser_output);
  output_nft_free(output);
}

void test_output_nft_validation() {
  // create random NFT address
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(sender_addr.address, ADDRESS_NFT_BYTES);

  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_NFT_BYTES);

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  iota_crypto_randombytes(nft_id, ADDRESS_NFT_BYTES);

  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &sender_addr) == 0);
  TEST_ASSERT(feat_blk_list_add_tag(&feat_blocks, test_tag, sizeof(test_tag)) == 0);

  // create Immutable Feature Blocks
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta, sizeof(test_immut_meta)) == 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  //=====Test NULL NFT ID=====
  output_nft_t* output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);
  output_nft_free(output);
  output = output_nft_new(123456789, native_tokens, NULL, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NULL(output);

  //=====Test address matches NFT ID=====
  printf(
      "FIXME : Test case for Address field of the Address Unlock Condition must not be the same as the NFT address "
      "derived from NFT ID\n");

  //=====Test NULL Unlock Block=====
  output = output_nft_new(123456789, native_tokens, nft_id, NULL, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NULL(output);

  //=====Test unlock condition with state controller=====
  cond_blk_list_free(unlock_conds);
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_state) == 0);
  output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NULL(output);

  //=====Test unlock condition with governor unlock =====
  cond_blk_list_free(unlock_conds);
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_gov) == 0);
  output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NULL(output);

  //=====Test without address unlock condition=====
  cond_blk_list_free(unlock_conds);
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) == 0);
  output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NULL(output);

  //=====Test maximum unlock blocks=====
  cond_blk_list_free(unlock_conds);
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) != 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_storage) != 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) != 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) != 0);

  //=====Test maximum feature blocks count=====
  iota_crypto_randombytes(sender_addr.address, ADDRESS_NFT_BYTES);
  // Adding one more block should fail.
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &sender_addr) != 0);
  byte_t test_meta_new[] = "Test metadata new";
  byte_t test_tag_new[] = "Test TAG New";
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta_new, sizeof(test_meta_new)) != 0);
  TEST_ASSERT(feat_blk_list_add_tag(&feat_blocks, test_tag_new, sizeof(test_tag_new)) != 0);

  //=====Test maximum immutable feature blocks count=====
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_NFT_BYTES);
  // Adding one more block should fail.
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) != 0);
  byte_t test_immut_meta_new[] = "Test metadata new";
  TEST_ASSERT(feat_blk_list_add_metadata(&immut_feat_blocks, test_immut_meta_new, sizeof(test_immut_meta_new)) != 0);

  // clean up
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_nft_free(output);
}

void test_output_nft_clone() {
  //=====NULL NFT Output object=====
  output_nft_t* new_output = output_nft_clone(NULL);
  TEST_ASSERT_NULL(new_output);

  //=====Test NFT Output object=====
  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  iota_crypto_randombytes(nft_id, ADDRESS_NFT_BYTES);

  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);

  // create Feature Blocks
  // create random sender address
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ADDRESS_ED25519_BYTES);
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &sender_addr) == 0);

  // create Immutable Feature Blocks
  // create random issuer address
  address_t issuer_addr = {};
  issuer_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(issuer_addr.address, ADDRESS_ED25519_BYTES);
  feat_blk_list_t* immut_feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_issuer(&immut_feat_blocks, &issuer_addr) == 0);

  // create NFT Output
  output_nft_t* output = output_nft_new(123456789, native_tokens, nft_id, unlock_conds, feat_blocks, immut_feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // clone NFT Output object
  new_output = output_nft_clone(output);

  // validate new NFT Output object
  TEST_ASSERT_EQUAL_UINT64(output->amount, new_output->amount);

  // validate native tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_NOT_NULL(new_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(output->native_tokens), native_tokens_count(new_output->native_tokens));

  TEST_ASSERT_EQUAL_MEMORY(output->nft_id, new_output->nft_id, ADDRESS_NFT_BYTES);

  // validate feature blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_NOT_NULL(new_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(output->feature_blocks), feat_blk_list_len(new_output->feature_blocks));

  // validate immutable feature blocks
  TEST_ASSERT_NOT_NULL(output->immutable_blocks);
  TEST_ASSERT_NOT_NULL(new_output->immutable_blocks);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(output->immutable_blocks), feat_blk_list_len(new_output->immutable_blocks));

  // clean up
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  feat_blk_list_free(immut_feat_blocks);
  output_nft_free(new_output);
  output_nft_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_nft);
  RUN_TEST(test_output_nft_without_native_tokens);
  RUN_TEST(test_output_nft_without_feature_blocks);
  RUN_TEST(test_output_nft_without_immutable_feature_blocks);
  RUN_TEST(test_output_nft_validation);
  RUN_TEST(test_output_nft_clone);

  return UNITY_END();
}
