// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/constants.h"
#include "core/models/outputs/output_basic.h"
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
native_tokens_list_t* native_tokens = NULL;
uint256_t* amount1 = NULL;
uint256_t* amount2 = NULL;
uint256_t* amount3 = NULL;

unlock_cond_t* unlock_addr = NULL;
unlock_cond_t* unlock_storage = NULL;
address_t test_addr = {};
uint64_t unlock_storage_amount = 9876543210;
unlock_cond_t* unlock_timelock = NULL;
uint32_t unlock_time_ms = 1200;
uint32_t unlock_time_unix = 164330008;
unlock_cond_t* unlock_expir = NULL;
unlock_cond_t* unlock_state = NULL;
unlock_cond_t* unlock_gov = NULL;

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
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);
  // create test unlock conditions
  unlock_addr = condition_addr_new(&test_addr);
  unlock_storage = condition_storage_new(&test_addr, unlock_storage_amount);
  unlock_timelock = condition_timelock_new(unlock_time_ms, unlock_time_unix);
  unlock_expir = condition_expir_new(&test_addr, unlock_time_ms, unlock_time_unix);
  unlock_state = condition_state_new(&test_addr);
  unlock_gov = condition_governor_new(&test_addr);
}

void tearDown(void) {
  uint256_free(amount1);
  uint256_free(amount2);
  uint256_free(amount3);
  native_tokens_free(native_tokens);
  condition_free(unlock_addr);
  condition_free(unlock_storage);
  condition_free(unlock_timelock);
  condition_free(unlock_expir);
  condition_free(unlock_state);
  condition_free(unlock_gov);
}

void test_output_basic() {
  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_timelock) == 0);

  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);
  // create Features
  feature_list_t* feat_list = feature_list_new();
  TEST_ASSERT(feature_list_add_tag(&feat_list, test_tag, sizeof(test_tag)) == 0);
  TEST_ASSERT(feature_list_add_sender(&feat_list, &addr) == 0);
  TEST_ASSERT(feature_list_add_metadata(&feat_list, test_meta, sizeof(test_meta)) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, native_tokens, unlock_conds, feat_list);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

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

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(4, condition_list_len(output->unlock_conditions));
  // 0: Storage Return Unlock
  unlock_cond_t* cond = condition_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // 1: Address Unlock
  cond = condition_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 2: Expiration Unlock
  cond = condition_list_get(output->unlock_conditions, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_expir_t*)cond->obj)->addr));
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_expir_t*)cond->obj)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_expir_t*)cond->obj)->time);
  // 3: Timelock Unlock
  cond = condition_list_get(output->unlock_conditions, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond->type);
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_timelock_t*)cond->obj)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_timelock_t*)cond->obj)->time);

  // features should be in adding order
  TEST_ASSERT_NOT_NULL(output->features);
  TEST_ASSERT_EQUAL_UINT8(3, feature_list_len(output->features));
  // 0: Tag
  output_feature_t* feat = feature_list_get(output->features, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_TYPE, feat->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feature_tag_t*)feat->obj)->tag, ((feature_tag_t*)feat->obj)->tag_len);
  // 1: Sender
  feat = feature_list_get(output->features, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_TYPE, feat->type);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)feat->obj));
  // 2: Metadata
  feat = feature_list_get(output->features, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_TYPE, feat->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feature_metadata_t*)feat->obj)->data,
                           ((feature_metadata_t*)feat->obj)->data_len);

  // syntactic validation
  TEST_ASSERT_TRUE(output_basic_syntactic(output));

  // serialize Basic Output and validate it
  size_t expected_serial_len = output_basic_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Basic Output and validate it
  output_basic_t* deser_output = output_basic_deserialize(serialized_buf, expected_serial_len - 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_basic_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  tokens = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, &tokens->token->amount, sizeof(uint256_t));

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on unlock condition type
  TEST_ASSERT_EQUAL_UINT8(4, condition_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 1: Storage Return Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // 2: Timelock Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_TIMELOCK, cond->type);
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_timelock_t*)cond->obj)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_timelock_t*)cond->obj)->time);
  // 3: Expiration Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_EXPIRATION, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_expir_t*)cond->obj)->addr));
  TEST_ASSERT(unlock_time_ms == ((unlock_cond_expir_t*)cond->obj)->milestone);
  TEST_ASSERT(unlock_time_unix == ((unlock_cond_expir_t*)cond->obj)->time);

  // deserialized features
  TEST_ASSERT_NOT_NULL(deser_output->features);
  // should be sorted based on feature type
  TEST_ASSERT_EQUAL_UINT8(3, feature_list_len(deser_output->features));
  // 0: Sender
  feat = feature_list_get(deser_output->features, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_TYPE, feat->type);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)feat->obj));
  // 1: Metadata
  feat = feature_list_get(deser_output->features, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_TYPE, feat->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feature_metadata_t*)feat->obj)->data,
                           ((feature_metadata_t*)feat->obj)->data_len);
  // 2: Tag
  feat = feature_list_get(deser_output->features, 2);
  TEST_ASSERT_EQUAL_UINT8(FEAT_TAG_TYPE, feat->type);
  TEST_ASSERT_EQUAL_MEMORY(test_tag, ((feature_tag_t*)feat->obj)->tag, ((feature_tag_t*)feat->obj)->tag_len);

  output_basic_print(output, 0);
  // clean up
  free(serialized_buf);
  condition_list_free(unlock_conds);
  feature_list_free(feat_list);
  output_basic_free(output);
  output_basic_free(deser_output);
}

void test_output_basic_without_native_tokens() {
  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);

  // create Features
  feature_list_t* feat_list = feature_list_new();
  feature_list_add_metadata(&feat_list, test_meta, sizeof(test_meta));

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, NULL, unlock_conds, feat_list);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

  // should be NULL
  TEST_ASSERT_NULL(output->native_tokens);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_t* cond = condition_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 1: Storage Return Unlock
  cond = condition_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // index out of list
  TEST_ASSERT_NULL(condition_list_get(output->unlock_conditions, 2));

  // features should be in adding order
  TEST_ASSERT_NOT_NULL(output->features);
  TEST_ASSERT_EQUAL_UINT8(1, feature_list_len(output->features));
  // 0: Metadata
  output_feature_t* feat = feature_list_get(output->features, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_TYPE, feat->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feature_metadata_t*)feat->obj)->data,
                           ((feature_metadata_t*)feat->obj)->data_len);
  // index out of list
  TEST_ASSERT_NULL(feature_list_get(output->features, 1));

  // syntactic validation
  TEST_ASSERT_TRUE(output_basic_syntactic(output));

  // serialize Basic Output and validate it
  size_t expected_serial_len = output_basic_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Basic Output and validate it
  output_basic_t* deser_output = output_basic_deserialize(serialized_buf, expected_serial_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_basic_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NULL(deser_output->native_tokens);

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on unlock condition type
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 1: Storage Return Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // 1: NULL
  TEST_ASSERT_NULL(condition_list_get(deser_output->unlock_conditions, 2));

  // deserialized features
  TEST_ASSERT_NOT_NULL(deser_output->features);
  // should be sorted based on feature type
  TEST_ASSERT_EQUAL_UINT8(1, feature_list_len(deser_output->features));
  // 0: Metadata
  feat = feature_list_get(deser_output->features, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_METADATA_TYPE, feat->type);
  TEST_ASSERT_EQUAL_MEMORY(test_meta, ((feature_metadata_t*)feat->obj)->data,
                           ((feature_metadata_t*)feat->obj)->data_len);
  // 1: NULL
  TEST_ASSERT_NULL(feature_list_get(deser_output->features, 1));

  output_basic_print(output, 0);
  // clean up
  free(serialized_buf);
  condition_list_free(unlock_conds);
  feature_list_free(feat_list);
  output_basic_free(output);
  output_basic_free(deser_output);
}

void test_output_basic_without_features() {
  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, native_tokens, unlock_conds, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

  // native tokens
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

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_t* cond = condition_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 1: Storage Return Unlock
  cond = condition_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // index out of list
  TEST_ASSERT_NULL(condition_list_get(output->unlock_conditions, 2));

  // features should be NULL
  TEST_ASSERT_NULL(output->features);
  TEST_ASSERT_EQUAL_UINT8(0, feature_list_len(output->features));
  // index out of list
  TEST_ASSERT_NULL(feature_list_get(output->features, 0));

  // syntactic validation
  TEST_ASSERT_TRUE(output_basic_syntactic(output));

  // serialize Basic Output and validate it
  size_t expected_serial_len = output_basic_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Basic Output and validate it
  output_basic_t* deser_output = output_basic_deserialize(serialized_buf, expected_serial_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_basic_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(3, native_tokens_count(deser_output->native_tokens));
  // native tokens are sorted in lexicographical order based on token ID
  tokens = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, &tokens->token->amount, sizeof(uint256_t));
  tokens = tokens->next;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, tokens->token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, &tokens->token->amount, sizeof(uint256_t));

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on unlock condition type
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 1: Storage Return Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // 1: NULL
  TEST_ASSERT_NULL(condition_list_get(deser_output->unlock_conditions, 2));

  // deserialized features
  TEST_ASSERT_NULL(deser_output->features);
  TEST_ASSERT_EQUAL_UINT8(0, feature_list_len(deser_output->features));
  TEST_ASSERT_NULL(feature_list_get(deser_output->features, 1));

  output_basic_print(output, 0);
  // clean up
  free(serialized_buf);
  condition_list_free(unlock_conds);
  output_basic_free(output);
  output_basic_free(deser_output);
}

void test_output_basic_without_native_tokens_and_features() {
  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, NULL, unlock_conds, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT(output->amount == 123456789);

  // native tokens
  TEST_ASSERT_NULL(output->native_tokens);

  // unlock conditions should be in adding order
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(output->unlock_conditions));
  // 0: Address Unlock
  unlock_cond_t* cond = condition_list_get(output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 1: Storage Return Unlock
  cond = condition_list_get(output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // index out of list
  TEST_ASSERT_NULL(condition_list_get(output->unlock_conditions, 2));

  // features should be NULL
  TEST_ASSERT_NULL(output->features);
  TEST_ASSERT_EQUAL_UINT8(0, feature_list_len(output->features));
  // index out of list
  TEST_ASSERT_NULL(feature_list_get(output->features, 0));

  // syntactic validation
  TEST_ASSERT_TRUE(output_basic_syntactic(output));

  // serialize Basic Output and validate it
  size_t expected_serial_len = output_basic_serialize_len(output);
  TEST_ASSERT(expected_serial_len != 0);
  byte_t* serialized_buf = malloc(expected_serial_len);
  TEST_ASSERT_NOT_NULL(serialized_buf);
  // expect serialization fails
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len - 1) == 0);
  TEST_ASSERT(output_basic_serialize(output, serialized_buf, expected_serial_len) == expected_serial_len);

  // deserialize Basic Output and validate it
  output_basic_t* deser_output = output_basic_deserialize(serialized_buf, expected_serial_len - 1);
  // expect deserialization fails
  TEST_ASSERT_NULL(deser_output);
  deser_output = output_basic_deserialize(serialized_buf, expected_serial_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  // deserialized amount
  TEST_ASSERT_EQUAL_UINT64(output->amount, deser_output->amount);

  // deserialized native tokens
  TEST_ASSERT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(0, native_tokens_count(deser_output->native_tokens));

  // deserialized unlock conditions
  TEST_ASSERT_NOT_NULL(deser_output->unlock_conditions);
  // should be sorted based on unlock condition type
  TEST_ASSERT_EQUAL_UINT8(2, condition_list_len(deser_output->unlock_conditions));
  // 0: Address Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_ADDRESS, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, (address_t*)cond->obj));
  // 1: Storage Return Unlock
  cond = condition_list_get(deser_output->unlock_conditions, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_COND_STORAGE, cond->type);
  TEST_ASSERT_TRUE(address_equal(&test_addr, ((unlock_cond_storage_t*)cond->obj)->addr));
  TEST_ASSERT_EQUAL_UINT64(unlock_storage_amount, ((unlock_cond_storage_t*)cond->obj)->amount);
  // 1: NULL
  TEST_ASSERT_NULL(condition_list_get(deser_output->unlock_conditions, 2));

  // deserialized features
  TEST_ASSERT_NULL(deser_output->features);
  TEST_ASSERT_EQUAL_UINT8(0, feature_list_len(deser_output->features));
  TEST_ASSERT_NULL(feature_list_get(deser_output->features, 1));

  output_basic_print(output, 0);
  // clean up
  free(serialized_buf);
  condition_list_free(unlock_conds);
  output_basic_free(output);
  output_basic_free(deser_output);
}

void test_output_basic_unlock_conditions() {
  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();

  // invalid: empty unlock conditions
  TEST_ASSERT_NULL(output_basic_new(123456789, NULL, NULL, NULL));
  TEST_ASSERT_NULL(output_basic_new(123456789, NULL, unlock_conds, NULL));

  // invalid unlock conditions: State Controller/Governanor
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_state) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_gov) == 0);
  output_basic_t* output = output_basic_new(123456789, NULL, unlock_conds, NULL);
  TEST_ASSERT_NOT_NULL(output);
  // syntactic validation
  TEST_ASSERT_FALSE(output_basic_syntactic(output));
  condition_list_free(unlock_conds);
  output_basic_free(output);

  // invalid unlock condition: State Controller
  unlock_conds = condition_list_new();
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_state) == 0);
  output = output_basic_new(123456789, NULL, unlock_conds, NULL);
  TEST_ASSERT_NOT_NULL(output);
  // syntactic validation
  TEST_ASSERT_FALSE(output_basic_syntactic(output));
  condition_list_free(unlock_conds);
  output_basic_free(output);

  // invalid unlock condition: Governor
  unlock_conds = condition_list_new();
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_gov) == 0);
  output = output_basic_new(123456789, NULL, unlock_conds, NULL);
  TEST_ASSERT_NOT_NULL(output);
  // syntactic validation
  TEST_ASSERT_FALSE(output_basic_syntactic(output));
  condition_list_free(unlock_conds);
  output_basic_free(output);
}

void test_output_basic_clone() {
  //=====NULL Basic Output object=====
  output_basic_t* new_output = output_basic_clone(NULL);
  TEST_ASSERT_NULL(new_output);

  //=====Test Basic Output object=====
  // create unlock conditions
  unlock_cond_list_t* unlock_conds = condition_list_new();
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_storage) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_addr) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_expir) == 0);
  TEST_ASSERT(condition_list_add(&unlock_conds, unlock_timelock) == 0);

  // create Features
  feature_list_t* feat_list = feature_list_new();
  TEST_ASSERT(feature_list_add_tag(&feat_list, test_tag, sizeof(test_tag)) == 0);
  TEST_ASSERT(feature_list_add_sender(&feat_list, &test_addr) == 0);
  TEST_ASSERT(feature_list_add_metadata(&feat_list, test_meta, sizeof(test_meta)) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(123456789, native_tokens, unlock_conds, feat_list);
  TEST_ASSERT_NOT_NULL(output);

  // clone Basic Output object
  new_output = output_basic_clone(output);
  TEST_ASSERT_NOT_NULL(new_output);

  // validate Amount
  TEST_ASSERT(output->amount == new_output->amount);
  // validate Native Tokens
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_NOT_NULL(new_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT8(native_tokens_count(output->native_tokens), native_tokens_count(new_output->native_tokens));
  // validate Unlock Conditions
  TEST_ASSERT_NOT_NULL(output->unlock_conditions);
  TEST_ASSERT_NOT_NULL(new_output->unlock_conditions);
  TEST_ASSERT_EQUAL_UINT8(condition_list_len(output->unlock_conditions),
                          condition_list_len(new_output->unlock_conditions));

  // validate Features
  TEST_ASSERT_NOT_NULL(output->features);
  TEST_ASSERT_NOT_NULL(new_output->features);
  TEST_ASSERT_EQUAL_UINT8(feature_list_len(output->features), feature_list_len(new_output->features));

  // print new Basic Output
  output_basic_print(new_output, 0);

  // clean up
  condition_list_free(unlock_conds);
  feature_list_free(feat_list);
  output_basic_free(new_output);
  output_basic_free(output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_basic);
  RUN_TEST(test_output_basic_without_native_tokens);
  RUN_TEST(test_output_basic_without_features);
  RUN_TEST(test_output_basic_without_native_tokens_and_features);
  RUN_TEST(test_output_basic_unlock_conditions);
  RUN_TEST(test_output_basic_clone);

  return UNITY_END();
}
