// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>
#include <unity/unity.h>

#include "core/constants.h"
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
static byte_t exp_unlocks[109] = {
    0x4,  0x0,  0x0,  0x0,  0xE7, 0x45, 0x3D, 0x64, 0x4D, 0x7B, 0xE6, 0x70, 0x64, 0x80, 0x15, 0x74, 0x28, 0xD9, 0x68,
    0x87, 0x2E, 0x38, 0x9C, 0x7B, 0x27, 0x62, 0xD1, 0x4B, 0xBE, 0xC,  0xA4, 0x6B, 0x91, 0xDE, 0xA4, 0xC4, 0x74, 0x9,
    0x52, 0x4C, 0xA4, 0x4,  0xFB, 0x5E, 0x51, 0xE3, 0xC6, 0x65, 0xF1, 0x1F, 0xA6, 0x61, 0x4,  0xC3, 0xE,  0x8,  0xE9,
    0x0,  0x38, 0x4F, 0xDD, 0xEB, 0x5B, 0x93, 0xB6, 0xED, 0xA0, 0x54, 0xC5, 0x3,  0x3E, 0xBD, 0xD4, 0xD8, 0xA7, 0xA,
    0x7B, 0xA8, 0xBB, 0xCC, 0x7A, 0x34, 0x4D, 0x56, 0xE2, 0xBA, 0x11, 0xD2, 0x2A, 0xF3, 0xAB, 0xE4, 0x6E, 0x99, 0x21,
    0x56, 0x25, 0x73, 0xF2, 0x62, 0x1,  0x0,  0x0,  0x2,  0x0,  0x0,  0x3,  0x0,  0x0};

void test_unlocks() {
  unlock_list_t* unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));

  // add a signature unlock
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  sig[0] = 0;  // denotes ed25519 signature
  memcpy(sig + 1, test_pub_key, ED_PUBLIC_KEY_BYTES);
  memcpy(sig + (1 + ED_PUBLIC_KEY_BYTES), test_sig, ED_SIGNATURE_BYTES);
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));

  // add a reference unlock that reference to the 0 index of unlock list.
  unlock_list_add_reference(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));

  // add an alias unlock that reference to the 0 index of unlock list.
  unlock_list_add_alias(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(3, unlock_list_count(unlock_list));

  // add a NFT unlock that reference to the 0 index of unlock list.
  unlock_list_add_nft(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_list_count(unlock_list));

  unlock_list_print(unlock_list, 0);

  // serialization
  size_t len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len != 0);
  byte_t* unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  TEST_ASSERT_EQUAL_MEMORY(exp_unlocks, unlock_buf, sizeof(exp_unlocks));
  // dump_hex(unlock_buf, len);

  free(unlock_buf);

  unlock_list_free(unlock_list);
}

void test_unlock_validation() {
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  unlock_list_t* unlock_list;

  //=====Signature unlock validation=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);  // Add valid signature
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);  // Add valid signature
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);  // Add duplicated signature
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  // clean up
  unlock_list_free(unlock_list);
  unlock_list = NULL;

  //=====Reference unlock validation=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_reference(&unlock_list, 0);  // Add valid reference
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  unlock_list_add_reference(&unlock_list, 2);  // Add too big reference index
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  unlock_list_add_reference(&unlock_list, 1);  // Add reference index which does not point to signature unlock
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  // clean up
  unlock_list_free(unlock_list);
  unlock_list = NULL;

  //=====Alias unlock validation=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_alias(&unlock_list, 0);  // Add valid alias
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  unlock_list_add_alias(&unlock_list, 2);  // Add too big alias index
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  // clean up
  unlock_list_free(unlock_list);
  unlock_list = NULL;

  //=====NFT unlock validation=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_nft(&unlock_list, 0);  // Add valid NFT
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  unlock_list_add_nft(&unlock_list, 2);  // Add too big NFT index
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  // clean up
  unlock_list_free(unlock_list);
  unlock_list = NULL;
}

void test_unlock_serialize() {
  byte_t sig[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  unlock_list_t* unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));

  //=====1 signature=====
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  // serialization
  size_t len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES));
  byte_t* unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====1 signature with 1 reference=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 1 signature and 1 reference
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_reference(&unlock_list, 0);
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_REFERENCE_SERIALIZE_BYTES));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====1 signature with 2 reference=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 1 signature and 2 reference
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_reference(&unlock_list, 0);
  unlock_list_add_reference(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(3, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + (UNLOCK_REFERENCE_SERIALIZE_BYTES * 2)));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====1 signature with 1 alias=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 1 signature and 1 alias
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_alias(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_ALIAS_SERIALIZE_BYTES));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====1 signature with 1 NFT=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 1 signature and 1 NFT
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_nft(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_NFT_SERIALIZE_BYTES));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====1 signature with 1 reference, 1 alias and 1 NFT=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 1 signature and 1 reference, 1 alias and 1 NFT
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(unlock_list));
  unlock_list_add_reference(&unlock_list, 0);
  unlock_list_add_alias(&unlock_list, 0);
  unlock_list_add_nft(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + UNLOCK_SIGNATURE_SERIALIZE_BYTES + UNLOCK_REFERENCE_SERIALIZE_BYTES +
                      UNLOCK_ALIAS_SERIALIZE_BYTES + UNLOCK_NFT_SERIALIZE_BYTES));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====2 signature=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_UINT16(2, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2)));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====2 signature with 1 reference=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_list_add_reference(&unlock_list, 1);
  TEST_ASSERT_EQUAL_UINT16(3, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + UNLOCK_REFERENCE_SERIALIZE_BYTES));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====2 signature with 2 reference=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_list_add_reference(&unlock_list, 1);
  unlock_list_add_reference(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len ==
              (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_REFERENCE_SERIALIZE_BYTES * 2)));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====2 signature with 2 alias=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_list_add_alias(&unlock_list, 1);
  unlock_list_add_alias(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_ALIAS_SERIALIZE_BYTES * 2)));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====2 signature with 2 NFT=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_list_add_nft(&unlock_list, 1);
  unlock_list_add_nft(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(4, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len == (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_NFT_SERIALIZE_BYTES * 2)));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;

  //=====2 signature with 2 reference, 2 alias and 2 NFT=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));
  // added 2 signature
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig, ED25519_SIGNATURE_BLOCK_BYTES);
  sig[0] = 0;
  unlock_list_add_signature(&unlock_list, sig, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_list_add_reference(&unlock_list, 1);
  unlock_list_add_reference(&unlock_list, 0);
  unlock_list_add_alias(&unlock_list, 1);
  unlock_list_add_alias(&unlock_list, 0);
  unlock_list_add_nft(&unlock_list, 1);
  unlock_list_add_nft(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(8, unlock_list_count(unlock_list));
  // serialization
  len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len ==
              (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_REFERENCE_SERIALIZE_BYTES * 2) +
               (UNLOCK_ALIAS_SERIALIZE_BYTES * 2) + (UNLOCK_NFT_SERIALIZE_BYTES * 2)));
  unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);
  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_buf = NULL;
  unlock_list = NULL;
}

void test_unlock_deserialize() {
  byte_t sig1[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  byte_t sig2[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  unlock_list_t* unlock_list = unlock_list_new();

  //=====2 signature with 2 reference, 2 alias and 2 NFT=====
  unlock_list = unlock_list_new();
  TEST_ASSERT_NULL(unlock_list);
  TEST_ASSERT_EQUAL_UINT16(0, unlock_list_count(unlock_list));

  iota_crypto_randombytes(sig1, ED25519_SIGNATURE_BLOCK_BYTES);
  sig1[0] = UNLOCK_SIGNATURE_TYPE;
  unlock_list_add_signature(&unlock_list, sig1, ED25519_SIGNATURE_BLOCK_BYTES);
  iota_crypto_randombytes(sig2, ED25519_SIGNATURE_BLOCK_BYTES);
  sig2[0] = UNLOCK_SIGNATURE_TYPE;
  unlock_list_add_signature(&unlock_list, sig2, ED25519_SIGNATURE_BLOCK_BYTES);
  unlock_list_add_reference(&unlock_list, 1);
  unlock_list_add_reference(&unlock_list, 0);
  unlock_list_add_alias(&unlock_list, 1);
  unlock_list_add_alias(&unlock_list, 0);
  unlock_list_add_nft(&unlock_list, 1);
  unlock_list_add_nft(&unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT16(8, unlock_list_count(unlock_list));

  // serialization
  size_t len = unlock_list_serialize_length(unlock_list);
  TEST_ASSERT(len ==
              (sizeof(uint16_t) + (UNLOCK_SIGNATURE_SERIALIZE_BYTES * 2) + (UNLOCK_REFERENCE_SERIALIZE_BYTES * 2) +
               (UNLOCK_ALIAS_SERIALIZE_BYTES * 2) + (UNLOCK_NFT_SERIALIZE_BYTES * 2)));
  byte_t* unlock_buf = malloc(len);
  TEST_ASSERT_NOT_NULL(unlock_buf);
  TEST_ASSERT(unlock_list_serialize(unlock_list, unlock_buf) == len);

  // deserialization failed
  unlock_list_t* deser_unlock_list = unlock_list_deserialize(unlock_buf, len - 1);  // too small buffer length
  TEST_ASSERT_NULL(deser_unlock_list);

  // deserialization
  deser_unlock_list = unlock_list_deserialize(unlock_buf, len);
  TEST_ASSERT_NOT_NULL(deser_unlock_list);
  TEST_ASSERT_EQUAL_UINT8(8, unlock_list_count(deser_unlock_list));

  // validation for deserialization
  // Unlock #0
  unlock_t* unlock = unlock_list_get(deser_unlock_list, 0);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_SIGNATURE_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_MEMORY(sig1, unlock->obj, sizeof(sig1));

  // Unlock #1
  unlock = unlock_list_get(deser_unlock_list, 1);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_SIGNATURE_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_MEMORY(sig2, unlock->obj, sizeof(sig2));

  // Unlock #2
  unlock = unlock_list_get(deser_unlock_list, 2);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_REFERENCE_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_UINT16(1, *(uint16_t*)unlock->obj);

  // Unlock #3
  unlock = unlock_list_get(deser_unlock_list, 3);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_REFERENCE_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_UINT16(0, *(uint16_t*)unlock->obj);

  // Unlock #4
  unlock = unlock_list_get(deser_unlock_list, 4);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_ALIAS_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_UINT16(1, *(uint16_t*)unlock->obj);

  // Unlock #5
  unlock = unlock_list_get(deser_unlock_list, 5);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_ALIAS_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_UINT16(0, *(uint16_t*)unlock->obj);

  // Unlock #6
  unlock = unlock_list_get(deser_unlock_list, 6);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_NFT_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_UINT16(1, *(uint16_t*)unlock->obj);

  // Unlock #7
  unlock = unlock_list_get(deser_unlock_list, 7);
  TEST_ASSERT_EQUAL_UINT8(UNLOCK_NFT_TYPE, unlock->type);
  TEST_ASSERT_EQUAL_UINT16(0, *(uint16_t*)unlock->obj);

  // clean up
  free(unlock_buf);
  unlock_list_free(unlock_list);
  unlock_list_free(deser_unlock_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_unlocks);
  RUN_TEST(test_unlock_validation);
  RUN_TEST(test_unlock_serialize);
  RUN_TEST(test_unlock_deserialize);

  return UNITY_END();
}
