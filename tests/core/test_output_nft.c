// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_nft.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_output_nft() {
  // create random NFT address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, ADDRESS_NFT_BYTES);

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

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  memcpy(nft_id, addr.address, ADDRESS_NFT_BYTES);

  // create metadata
  byte_buf_t* metadata = byte_buf_new_with_data("Test metadata...", sizeof("Test metadata..."));

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);

  // create NFT Output
  output_nft_t* output =
      output_nft_new(&addr, 123456789, native_tokens, nft_id, metadata->data, metadata->len, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_NFT_BYTES);
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

  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), output->immutable_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", output->immutable_metadata->data, output->immutable_metadata->len);

  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_NFT_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

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
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, deser_output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(deser_output->address, &addr, 1 + ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));
  token = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));

  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), deser_output->immutable_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", deser_output->immutable_metadata->data,
                           deser_output->immutable_metadata->len);

  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, feat_block->block, ADDRESS_NFT_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

  output_nft_print(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_nft_buf);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);
  output_nft_free(output);
  output_nft_free(deser_output);
}

void test_output_nft_without_native_tokens() {
  // create random NFT address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, ADDRESS_NFT_BYTES);

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  memcpy(nft_id, addr.address, ADDRESS_NFT_BYTES);

  // create metadata
  byte_buf_t* metadata = byte_buf_new_with_data("Test metadata...", sizeof("Test metadata..."));

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);

  // create NFT Output
  output_nft_t* output = output_nft_new(&addr, 123456789, NULL, nft_id, metadata->data, metadata->len, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);

  TEST_ASSERT_NULL(output->native_tokens);

  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), output->immutable_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", output->immutable_metadata->data, output->immutable_metadata->len);

  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_NFT_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

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
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, deser_output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(deser_output->address, &addr, 1 + ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  TEST_ASSERT_NULL(deser_output->native_tokens);

  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), deser_output->immutable_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", deser_output->immutable_metadata->data,
                           deser_output->immutable_metadata->len);

  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_NFT_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

  output_nft_print(output);

  // clean up
  free(output_nft_buf);
  byte_buf_free(metadata);
  free_feat_blk_list(feat_blocks);
  output_nft_free(output);
  output_nft_free(deser_output);
}

void test_output_nft_without_metadata() {
  // create random NFT address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, ADDRESS_NFT_BYTES);

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

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  memcpy(nft_id, addr.address, ADDRESS_NFT_BYTES);

  // create Feature Blocks
  feat_blk_list_t* feat_blocks = new_feat_blk_list();
  feat_blk_list_add_sender(&feat_blocks, &addr);
  feat_blk_list_add_ddr(&feat_blocks, 1000000);

  // create NFT Output
  output_nft_t* output = output_nft_new(&addr, 123456789, native_tokens, nft_id, NULL, 0, feat_blocks);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_NFT_BYTES);
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

  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_NULL(output->immutable_metadata);

  TEST_ASSERT_NOT_NULL(output->feature_blocks);
  TEST_ASSERT_EQUAL_UINT8(2, feat_blk_list_len(output->feature_blocks));
  feat_block_t* feat_block = feat_blk_list_get(output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_NFT_BYTES);
  feat_block = feat_blk_list_get(output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

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
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, deser_output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(deser_output->address, &addr, 1 + ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));
  token = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));

  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_NULL(deser_output->immutable_metadata);

  TEST_ASSERT_NOT_NULL(deser_output->feature_blocks);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 0);
  TEST_ASSERT_EQUAL_UINT8(FEAT_SENDER_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_MEMORY(&addr, *(&feat_block->block), ADDRESS_NFT_BYTES);
  feat_block = feat_blk_list_get(deser_output->feature_blocks, 1);
  TEST_ASSERT_EQUAL_UINT8(FEAT_DUST_DEP_RET_BLOCK, feat_block->type);
  TEST_ASSERT_EQUAL_UINT64(1000000, *((uint64_t*)feat_block->block));

  output_nft_print(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_nft_buf);
  native_tokens_free(&native_tokens);
  free_feat_blk_list(feat_blocks);
  output_nft_free(output);
  output_nft_free(deser_output);
}

void test_output_nft_without_feature_blocks() {
  // create random NFT address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, ADDRESS_NFT_BYTES);

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

  // create NFT ID
  byte_t nft_id[ADDRESS_NFT_BYTES];
  memcpy(nft_id, addr.address, ADDRESS_NFT_BYTES);

  // create metadata
  byte_buf_t* metadata = byte_buf_new_with_data("Test metadata...", sizeof("Test metadata..."));

  // create NFT Output
  output_nft_t* output = output_nft_new(&addr, 123456789, native_tokens, nft_id, metadata->data, metadata->len, NULL);

  // validation
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_NFT_BYTES);
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

  TEST_ASSERT_EQUAL_MEMORY(nft_id, output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), output->immutable_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", output->immutable_metadata->data, output->immutable_metadata->len);

  TEST_ASSERT_NULL(output->feature_blocks);

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
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_NFT, deser_output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(deser_output->address, &addr, 1 + ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);

  TEST_ASSERT_NOT_NULL(deser_output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));
  token = deser_output->native_tokens;
  TEST_ASSERT_EQUAL_MEMORY(token_id1, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount1, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id2, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount2, token->amount, sizeof(uint256_t));
  token = token->hh.next;
  TEST_ASSERT_EQUAL_MEMORY(token_id3, token->token_id, NATIVE_TOKEN_ID_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(amount3, token->amount, sizeof(uint256_t));

  TEST_ASSERT_EQUAL_MEMORY(nft_id, deser_output->nft_id, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_INT32(sizeof("Test metadata..."), deser_output->immutable_metadata->len);
  TEST_ASSERT_EQUAL_MEMORY("Test metadata...", deser_output->immutable_metadata->data,
                           deser_output->immutable_metadata->len);

  TEST_ASSERT_NULL(deser_output->feature_blocks);

  output_nft_print(output);

  // clean up
  free(amount1);
  free(amount2);
  free(amount3);
  free(output_nft_buf);
  byte_buf_free(metadata);
  native_tokens_free(&native_tokens);
  output_nft_free(output);
  output_nft_free(deser_output);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_nft);
  RUN_TEST(test_output_nft_without_native_tokens);
  RUN_TEST(test_output_nft_without_metadata);
  RUN_TEST(test_output_nft_without_feature_blocks);

  return UNITY_END();
}
