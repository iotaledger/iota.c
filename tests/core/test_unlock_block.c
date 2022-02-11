// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <unity/unity.h>

#include "core/models/unlock_block.h"

void setUp(void) {}

void tearDown(void) {}

static byte_t test_pub_key[ED_PUBLIC_KEY_BYTES] = {0xe7, 0x45, 0x3d, 0x64, 0x4d, 0x7b, 0xe6, 0x70, 0x64, 0x80, 0x15,
                                                   0x74, 0x28, 0xd9, 0x68, 0x87, 0x2e, 0x38, 0x9c, 0x7b, 0x27, 0x62,
                                                   0xd1, 0x4b, 0xbe, 0xc,  0xa4, 0x6b, 0x91, 0xde, 0xa4, 0xc4};
static byte_t test_sig[ED_SIGNATURE_BYTES] = {
    0x74, 0x9,  0x52, 0x4c, 0xa4, 0x4,  0xfb, 0x5e, 0x51, 0xe3, 0xc6, 0x65, 0xf1, 0x1f, 0xa6, 0x61,
    0x4,  0xc3, 0xe,  0x8,  0xe9, 0x0,  0x38, 0x4f, 0xdd, 0xeb, 0x5b, 0x93, 0xb6, 0xed, 0xa0, 0x54,
    0xc5, 0x3,  0x3e, 0xbd, 0xd4, 0xd8, 0xa7, 0xa,  0x7b, 0xa8, 0xbb, 0xcc, 0x7a, 0x34, 0x4d, 0x56,
    0xe2, 0xba, 0x11, 0xd2, 0x2a, 0xf3, 0xab, 0xe4, 0x6e, 0x99, 0x21, 0x56, 0x25, 0x73, 0xf2, 0x62};
static byte_t exp_block[109] = {
    0x4,  0x0,  0x0,  0x0,  0xE7, 0x45, 0x3D, 0x64, 0x4D, 0x7B, 0xE6, 0x70, 0x64, 0x80, 0x15, 0x74, 0x28, 0xD9, 0x68,
    0x87, 0x2E, 0x38, 0x9C, 0x7B, 0x27, 0x62, 0xD1, 0x4B, 0xBE, 0xC,  0xA4, 0x6B, 0x91, 0xDE, 0xA4, 0xC4, 0x74, 0x9,
    0x52, 0x4C, 0xA4, 0x4,  0xFB, 0x5E, 0x51, 0xE3, 0xC6, 0x65, 0xF1, 0x1F, 0xA6, 0x61, 0x4,  0xC3, 0xE,  0x8,  0xE9,
    0x0,  0x38, 0x4F, 0xDD, 0xEB, 0x5B, 0x93, 0xB6, 0xED, 0xA0, 0x54, 0xC5, 0x3,  0x3E, 0xBD, 0xD4, 0xD8, 0xA7, 0xA,
    0x7B, 0xA8, 0xBB, 0xCC, 0x7A, 0x34, 0x4D, 0x56, 0xE2, 0xBA, 0x11, 0xD2, 0x2A, 0xF3, 0xAB, 0xE4, 0x6E, 0x99, 0x21,
    0x56, 0x25, 0x73, 0xF2, 0x62, 0x1,  0x0,  0x0,  0x2,  0x0,  0x0,  0x3,  0x0,  0x0};

void test_unlock_block() {
  unlock_list_t* blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));

  // add a signature block
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  sig[0] = 0;  // denotes ed25519 signature
  memcpy(sig + 1, test_pub_key, ED_PUBLIC_KEY_BYTES);
  memcpy(sig + (1 + ED_PUBLIC_KEY_BYTES), test_sig, ED_SIGNATURE_BYTES);
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));

  // add a reference block that reference to the 0 index of blocks.
  unlock_blocks_add_reference(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));

  // add an alias block that reference to the 0 index of blocks.
  unlock_blocks_add_alias(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(3, unlock_blocks_count(blocks));

  // add a NFT block that reference to the 0 index of blocks.
  unlock_blocks_add_nft(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_blocks_count(blocks));

  unlock_blocks_print(blocks, 0);

  // serialization
  size_t len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len != 0);
  byte_t* block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  TEST_ASSERT_EQUAL_MEMORY(exp_block, block_buf, sizeof(exp_block));
  // dump_hex(block_buf, len);

  free(block_buf);

  unlock_blocks_free(blocks);
}

void test_unlock_block_validation() {
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  unlock_list_t* blocks;

  //=====Signature unlock block validation=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);  // Add valid signature
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);  // Add valid signature
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);  // Add duplicated signature
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  // clean up
  unlock_blocks_free(blocks);
  blocks = NULL;

  //=====Reference unlock block validation=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_reference(&blocks, 0);  // Add valid reference
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  unlock_blocks_add_reference(&blocks, 2);  // Add too big reference index
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  unlock_blocks_add_reference(&blocks, 1);  // Add reference index which does not point to signature unlock block
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  // clean up
  unlock_blocks_free(blocks);
  blocks = NULL;

  //=====Alias unlock block validation=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_alias(&blocks, 0);  // Add valid alias
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  unlock_blocks_add_alias(&blocks, 2);  // Add too big alias index
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  // clean up
  unlock_blocks_free(blocks);
  blocks = NULL;

  //=====NFT unlock block validation=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_nft(&blocks, 0);  // Add valid NFT
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  unlock_blocks_add_nft(&blocks, 2);  // Add too big NFT index
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  // clean up
  unlock_blocks_free(blocks);
  blocks = NULL;
}

void test_unlock_block_serialize() {
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  unlock_list_t* blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));

  //=====1 signature=====
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  // serialization
  size_t len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES));
  byte_t* block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====1 signature with 1 reference=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 1 signature and 1 reference
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_reference(&blocks, 0);
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_REFERENCE_SERIALIZE_BYTES));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====1 signature with 2 reference=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 1 signature and 2 reference
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_reference(&blocks, 0);
  unlock_blocks_add_reference(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(3, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + (UNLOCK_REFERENCE_SERIALIZE_BYTES * 2)));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====1 signature with 1 alias=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 1 signature and 1 alias
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_alias(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_ALIAS_SERIALIZE_BYTES));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====1 signature with 1 NFT=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 1 signature and 1 NFT
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_nft(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_NFT_SERIALIZE_BYTES));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====1 signature with 1 reference, 1 alias and 1 NFT=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 1 signature and 1 reference, 1 alias and 1 NFT
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(blocks));
  unlock_blocks_add_reference(&blocks, 0);
  unlock_blocks_add_alias(&blocks, 0);
  unlock_blocks_add_nft(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_REFERENCE_SERIALIZE_BYTES +
                      UNLOCK_ALIAS_SERIALIZE_BYTES + UNLOCK_NFT_SERIALIZE_BYTES));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====2 signature=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2)));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====2 signature with 1 reference=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_blocks_add_reference(&blocks, 1);
  TEST_ASSERT_EQUAL_UINT16(3, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + UNLOCK_REFERENCE_SERIALIZE_BYTES));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====2 signature with 2 reference=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_blocks_add_reference(&blocks, 1);
  unlock_blocks_add_reference(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len ==
              (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_REFERENCE_SERIALIZE_BYTES * 2)));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====2 signature with 2 alias=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_blocks_add_alias(&blocks, 1);
  unlock_blocks_add_alias(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_ALIAS_SERIALIZE_BYTES * 2)));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====2 signature with 2 NFT=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_blocks_add_nft(&blocks, 1);
  unlock_blocks_add_nft(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_NFT_SERIALIZE_BYTES * 2)));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;

  //=====2 signature with 2 reference, 2 alias and 2 NFT=====
  blocks = unlock_blocks_new();
  TEST_ASSERT_NULL(blocks);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_blocks_count(blocks));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_blocks_add_signature(&blocks, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_blocks_add_reference(&blocks, 1);
  unlock_blocks_add_reference(&blocks, 0);
  unlock_blocks_add_alias(&blocks, 1);
  unlock_blocks_add_alias(&blocks, 0);
  unlock_blocks_add_nft(&blocks, 1);
  unlock_blocks_add_nft(&blocks, 0);
  TEST_ASSERT_EQUAL_UINT16(8, unlock_blocks_count(blocks));
  // serialization
  len = unlock_blocks_serialize_length(blocks);
  TEST_ASSERT(len ==
              (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_REFERENCE_SERIALIZE_BYTES * 2) +
               (UNLOCK_ALIAS_SERIALIZE_BYTES * 2) + (UNLOCK_NFT_SERIALIZE_BYTES * 2)));
  block_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(block_buf);
  TEST_ASSERT(unlock_blocks_serialize(blocks, block_buf) == len);
  // clean up
  free(block_buf);
  unlock_blocks_free(blocks);
  block_buf = NULL;
  blocks = NULL;
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_unlock_block);
  RUN_TEST(test_unlock_block_validation);
  RUN_TEST(test_unlock_block_serialize);

  return UNITY_END();
}
