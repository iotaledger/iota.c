// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_extended.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

// global test sets
byte_t token_id1[NATIVE_TOKEN_ID_BYTES] = {0xDD, 0xA7, 0xC5, 0x79, 0x47, 0x9E, 0xC,  0x93, 0xCE, 0xA7, 0x93, 0x95, 0x41,
                                           0xF8, 0x93, 0x4D, 0xF,  0x7E, 0x3A, 0x4,  0xCA, 0x52, 0xF8, 0x8B, 0x9B, 0x0,
                                           0x25, 0xC0, 0xBE, 0x4A, 0xF6, 0x23, 0x59, 0x98, 0x6F, 0x64, 0xEF, 0x14};
byte_t token_id2[NATIVE_TOKEN_ID_BYTES] = {0x74, 0x6B, 0xA0, 0xD9, 0x51, 0x41, 0xCB, 0x5B, 0x4B, 0xF7, 0x1C, 0x9D, 0x3E,
                                           0x76, 0x81, 0xBE, 0xB6, 0xA3, 0xAE, 0x5A, 0x6D, 0x7C, 0x89, 0xD0, 0x98, 0x42,
                                           0xDF, 0x86, 0x27, 0x5A, 0xF,  0x9,  0xCB, 0xE0, 0xF9, 0x1A, 0x6C, 0x6B};
byte_t token_id3[NATIVE_TOKEN_ID_BYTES] = {0xBA, 0x26, 0x7E, 0x59, 0xE5, 0x31, 0x77, 0xB3, 0x2A, 0xA9, 0xBF, 0xE,  0x56,
                                           0x31, 0x18, 0xC9, 0xE0, 0xAD, 0xD,  0x76, 0x88, 0x7B, 0x65, 0xFD, 0x58, 0x75,
                                           0xB7, 0x13, 0x29, 0x73, 0x5B, 0x94, 0x2B, 0x81, 0x6A, 0x7F, 0xE6, 0x79};

byte_t test_meta[] = "Test metadata...";
byte_t test_tag[] = "Test TAG";
native_tokens_t* native_tokens = NULL;
uint256_t* amount1 = NULL;
uint256_t* amount2 = NULL;
uint256_t* amount3 = NULL;

unlock_cond_blk_t* unlock_addr = NULL;
unlock_cond_blk_t* unlock_dust = NULL;
address_t test_addr = {};
uint64_t unlock_dust_amount = 9876543210;
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
  unlock_dust = cond_blk_dust_new(&test_addr, unlock_dust_amount);
  unlock_timelock = cond_blk_timelock_new(unlock_time_ms, unlock_time_unix);
  unlock_expir = cond_blk_expir_new(&test_addr, unlock_time_ms, unlock_time_unix);
  unlock_state = cond_blk_state_new(&test_addr);
  unlock_gov = cond_blk_governor_new(&test_addr);
}

void tearDown(void) {
  free(amount1);
  free(amount2);
  free(amount3);
  native_tokens_free(&native_tokens);
  cond_blk_free(unlock_addr);
  cond_blk_free(unlock_dust);
  cond_blk_free(unlock_timelock);
  cond_blk_free(unlock_expir);
  cond_blk_free(unlock_state);
  cond_blk_free(unlock_gov);
}

void test_output_extended() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);
  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_tag(&feat_blocks, test_tag, sizeof(test_tag)) == 0);
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &addr) == 0);
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);

  // create Extended Output
  output_extended_t* output = output_extended_new(123456789, native_tokens, unlock_conds, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

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

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(output->unlock_conditions));
  // 0: Dust Return Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // 1: Address Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
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
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)feat_block->block));
  // 2: Metadata
  feat_block = feat_blk_list_get(output->feature_blocks, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);

  // serialize Extended Output and validate it
  size_t expected_serial_len = output_extended_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(serialized_buf, expected_serial_len - 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_extended_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&deser_output->native_tokens));
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

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(4, cond_blk_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Dust Return Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // 2: Timelock Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond_block->type);
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_timelock_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_timelock_t*)cond_block->block)->time);
  // 3: Expiration Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_expir_t*)cond_block->block)->addr));
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_expir_t*)cond_block->block)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_expir_t*)cond_block->block)->time);

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(3, feat_blk_list_len(deser_output->feature_blocks));
  // 0: Sender
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)feat_block->block));
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

  output_extended_print(output, 0);
  // clean up
  free(serialized_buf);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  output_extended_free(output);
  output_extended_free(deser_output);
}

void test_output_extended_without_native_tokens() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta));

  // create Extended Output
  output_extended_t* output = output_extended_new(123456789, NULL, unlock_conds, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

  // should be NULL
  TEST_ASSERT_NULL(output->native_tokens);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Dust Return Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // index out of list
  TEST_ASSERT_NULL(cond_blk_list_get(output->unlock_conditions, 2));

  // feature blocks should be in adding order
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(output->feature_blocks));
  // 0: Metadata
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);
  // index out of list
  TEST_ASSERT_NULL(feat_blk_list_get(output->feature_blocks, 1));

  // serialize Extended Output and validate it
  size_t expected_serial_len = output_extended_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(serialized_buf, expected_serial_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_extended_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NULL(deser_output->native_tokens);

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Dust Return Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // 1: NULL
  TEST_ASSERT_NULL(cond_blk_list_get(deser_output->unlock_conditions, 2));

  // deserialized feature blocks
  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(1, feat_blk_list_len(deser_output->feature_blocks));
  // 0: Metadata
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feat_metadata_blk_t*)feat_block->block)->data,
                           ((feat_metadata_blk_t*)feat_block->block)->data_len);
  // 1: NULL
  TEST_ASSERT_NULL(feat_blk_list_get(deser_output->feature_blocks, 1));

  output_extended_print(output, 0);
  // clean up
  free(serialized_buf);
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  output_extended_free(output);
  output_extended_free(deser_output);
}

void test_output_extended_without_feature_blocks() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);

  // create Extended Output
  output_extended_t* output = output_extended_new(123456789, native_tokens, unlock_conds, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

  // native tokens
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

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Dust Return Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // index out of list
  TEST_ASSERT_NULL(cond_blk_list_get(output->unlock_conditions, 2));

  // feature blocks should be NULL
  TEST_ASSERT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(output->feature_blocks));
  // index out of list
  TEST_ASSERT_NULL(feat_blk_list_get(output->feature_blocks, 0));

  // serialize Extended Output and validate it
  size_t expected_serial_len = output_extended_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(serialized_buf, expected_serial_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_extended_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(&deser_output->native_tokens));
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

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Dust Return Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // 1: NULL
  TEST_ASSERT_NULL(cond_blk_list_get(deser_output->unlock_conditions, 2));

  // deserialized feature blocks
  TEST_ASSERT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(deser_output->feature_blocks));
  TEST_ASSERT_NULL(feat_blk_list_get(deser_output->feature_blocks, 1));

  output_extended_print(output, 0);
  // clean up
  free(serialized_buf);
  cond_blk_list_free(unlock_conds);
  output_extended_free(output);
  output_extended_free(deser_output);
}

void test_output_extended_without_native_tokens_and_feature_blocks() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);

  // create Extended Output
  output_extended_t* output = output_extended_new(123456789, NULL, unlock_conds, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

  // native tokens
  TEST_ASSERT_NULL(output->native_tokens);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_blk_t* cond_block = cond_blk_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Dust Return Unlock
  cond_block = cond_blk_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // index out of list
  TEST_ASSERT_NULL(cond_blk_list_get(output->unlock_conditions, 2));

  // feature blocks should be NULL
  TEST_ASSERT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(output->feature_blocks));
  // index out of list
  TEST_ASSERT_NULL(feat_blk_list_get(output->feature_blocks, 0));

  // serialize Extended Output and validate it
  size_t expected_serial_len = output_extended_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_extended_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(serialized_buf, expected_serial_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_extended_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(0, native_tokens_count(&deser_output->native_tokens));

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on block type
  TEST_ASSERT_EQUAL_UINT8(2, cond_blk_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond_block->block));
  // 1: Dust Return Unlock
  cond_block = cond_blk_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_DUST, cond_block->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_dust_t*)cond_block->block)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_dust_amount, ((unlock_cond_dust_t*)cond_block->block)->amount);
  // 1: NULL
  TEST_ASSERT_NULL(cond_blk_list_get(deser_output->unlock_conditions, 2));

  // deserialized feature blocks
  TEST_ASSERT_NULL(deser_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(0, feat_blk_list_len(deser_output->feature_blocks));
  TEST_ASSERT_NULL(feat_blk_list_get(deser_output->feature_blocks, 1));

  output_extended_print(output, 0);
  // clean up
  free(serialized_buf);
  cond_blk_list_free(unlock_conds);
  output_extended_free(output);
  output_extended_free(deser_output);
}

void test_output_extended_unlock_conditions() {
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();

  // invalid: empty unlock conditions
  TEST_ASSERT_NULL(output_extended_new(123456789, NULL, NULL, NULL));
  TEST_ASSERT_NULL(output_extended_new(123456789, NULL, unlock_conds, NULL));

  // invalid unlock conditions: State Controller/Governanor
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_state) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_gov) == 0);
  TEST_ASSERT_NULL(output_extended_new(123456789, NULL, unlock_conds, NULL));
  cond_blk_list_free(unlock_conds);

  // invalid unlock condition: State Controller
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_state) == 0);
  TEST_ASSERT_NULL(output_extended_new(123456789, NULL, unlock_conds, NULL));
  cond_blk_list_free(unlock_conds);

  // invalid unlock condition: Governor
  unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_gov) == 0);
  TEST_ASSERT_NULL(output_extended_new(123456789, NULL, unlock_conds, NULL));
  cond_blk_list_free(unlock_conds);
}

void test_output_extended_clone() {
  //=====NULL Extended Output object=====
  output_extended_t* new_output = output_extended_clone(NULL);
  TEST_ASSERT_NULL(new_output);

  //=====Test Extended Output object=====
  // create unlock conditions
  cond_blk_list_t* unlock_conds = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_dust) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(cond_blk_list_add(&unlock_conds, unlock_timelock) == 0);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = feat_blk_list_new();
  TEST_ASSERT(feat_blk_list_add_tag(&feat_blocks, test_tag, sizeof(test_tag)) == 0);
  TEST_ASSERT(feat_blk_list_add_sender(&feat_blocks, &test_addr) == 0);
  TEST_ASSERT(feat_blk_list_add_metadata(&feat_blocks, test_meta, sizeof(test_meta)) == 0);

  // create Extended Output
  output_extended_t* output = output_extended_new(123456789, native_tokens, unlock_conds, feat_blocks);
  TEST_ASSERT_NOT_NULL(output);

  // clone Extended Output object
  new_output = output_extended_clone(output);
  TEST_ASSERT_NOT_NULL(new_output);

  // validate Amount
  TEST_ASSERT(output->amount == new_output->amount);
  // validate Native Tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_NOT_NULL(new_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(&output->native_tokens), native_tokens_count(&new_output->native_tokens));
  // validate Unlock Conditions
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_NOT_NULL(new_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(cond_blk_list_len(output->unlock_conditions),
                          cond_blk_list_len(new_output->unlock_conditions));

  // validate Feature Blocks
  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_NOT_NULL(new_output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(feat_blk_list_len(output->feature_blocks), feat_blk_list_len(new_output->feature_blocks));

  // print new Extended Output
  output_extended_print(new_output, 0);

  // clean up
  cond_blk_list_free(unlock_conds);
  feat_blk_list_free(feat_blocks);
  output_extended_free(new_output);
  output_extended_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_extended);
  RUN_TEST(test_output_extended_without_native_tokens);
  RUN_TEST(test_output_extended_without_feature_blocks);
  RUN_TEST(test_output_extended_without_native_tokens_and_feature_blocks);
  RUN_TEST(test_output_extended_unlock_conditions);
  RUN_TEST(test_output_extended_clone);

  return UNITY_END();
}
