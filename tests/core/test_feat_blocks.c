// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/models/outputs/feat_blocks.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_sender() {
  // create a Sender feature block
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ADDRESS_PUBKEY_HASH_BYTES);
  feat_block_t* sender_blk = feat_blk_sender_new(&sender_addr);
  TEST_ASSERT_NOT_NULL(sender_blk);
  feat_blk_print(sender_blk);

  // validate sender object
  TEST_ASSERT(sender_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT_TRUE(address_equal((address_t*)sender_blk->block, &sender_addr));

  // serialization
  byte_t serialized_blk[64] = {};
  size_t serialized_len = feat_blk_serialize_len(sender_blk);
  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(sender_blk, serialized_blk, 1) == 0);
  TEST_ASSERT(feat_blk_serialize(sender_blk, serialized_blk, sizeof(serialized_blk)) == serialized_len);
  // expect deserialize failed
  TEST_ASSERT_NULL(feat_blk_deserialize(serialized_blk, serialized_len - 1));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate block type
  TEST_ASSERT(sender_blk->type == deser_blk->type);
  // validate address
  TEST_ASSERT_TRUE(address_equal((address_t*)sender_blk->block, (address_t*)deser_blk->block));

  // clean up
  feat_blk_free(sender_blk);
  feat_blk_free(deser_blk);
}

void test_issuer() {
  // create an Issuer feature block
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, NFT_ID_BYTES);
  feat_block_t* issuer_blk = feat_blk_issuer_new(&addr);
  TEST_ASSERT_NOT_NULL(issuer_blk);
  feat_blk_print(issuer_blk);

  // validate issuer object
  TEST_ASSERT(issuer_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT_TRUE(address_equal((address_t*)issuer_blk->block, &addr));

  // serialization
  byte_t serialized_blk[64] = {};
  size_t serialized_len = feat_blk_serialize_len(issuer_blk);
  TEST_ASSERT(feat_blk_serialize(issuer_blk, serialized_blk, 1) == 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(issuer_blk, serialized_blk, sizeof(serialized_blk)) == serialized_len);
  // expect deserialize failed
  TEST_ASSERT_NULL(feat_blk_deserialize(serialized_blk, serialized_len - 1));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate block type
  TEST_ASSERT(issuer_blk->type == deser_blk->type);
  // validate address
  TEST_ASSERT_TRUE(address_equal((address_t*)issuer_blk->block, (address_t*)deser_blk->block));

  // clean up
  feat_blk_free(issuer_blk);
  feat_blk_free(deser_blk);
}

void test_metadata_max() {
  // create a Metadata block
  byte_t meta_data[MAX_METADATA_LENGTH_BYTES] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  // metadata must smaller than MAX_METADATA_LENGTH_BYTES
  TEST_ASSERT_NULL(feat_blk_metadata_new(meta_data, sizeof(meta_data) + 1));

  // metadata with MAX_METADATA_LENGTH_BYTES
  feat_block_t* meta_blk = feat_blk_metadata_new(meta_data, sizeof(meta_data));
  TEST_ASSERT_NOT_NULL(meta_blk);
  feat_blk_print(meta_blk);

  // validate object
  TEST_ASSERT(meta_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)meta_blk->block)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(meta_data, ((feat_metadata_blk_t*)meta_blk->block)->data, sizeof(meta_data));

  // serialization
  size_t serialize_len = feat_blk_serialize_len(meta_blk);
  byte_t* serialized_blk = malloc(serialize_len);
  TEST_ASSERT_NOT_NULL(serialized_blk);
  // expect serialization failed
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, sizeof(meta_data)) == 0);
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, serialize_len) == serialize_len);
  // deserialize
  TEST_ASSERT_NULL(feat_blk_deserialize(serialized_blk, serialize_len - 1));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, serialize_len);
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(meta_blk->type == deser_blk->type);
  TEST_ASSERT(((feat_metadata_blk_t*)meta_blk->block)->data_len == ((feat_metadata_blk_t*)deser_blk->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(((feat_metadata_blk_t*)meta_blk->block)->data,
                           ((feat_metadata_blk_t*)deser_blk->block)->data,
                           ((feat_metadata_blk_t*)meta_blk->block)->data_len);

  // clean up
  free(serialized_blk);
  feat_blk_free(meta_blk);
  feat_blk_free(deser_blk);
}

void test_metadata_one_byte() {
  byte_t meta = 'A';
  feat_block_t* meta_blk = feat_blk_metadata_new(&meta, sizeof(meta));
  TEST_ASSERT_NOT_NULL(meta_blk);
  feat_blk_print(meta_blk);

  // validate object
  TEST_ASSERT(meta_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)meta_blk->block)->data_len == sizeof(meta));
  TEST_ASSERT_EQUAL_MEMORY(&meta, ((feat_metadata_blk_t*)meta_blk->block)->data, sizeof(meta));

  // serialization
  byte_t serialized_blk[32] = {};
  size_t serialize_len = feat_blk_serialize_len(meta_blk);
  // expect serialization failed
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, sizeof(meta)) == 0);
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, sizeof(serialized_blk)) == serialize_len);
  // deserialize
  TEST_ASSERT_NULL(feat_blk_deserialize(serialized_blk, serialize_len - 1));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, serialize_len);
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(meta_blk->type == deser_blk->type);
  TEST_ASSERT(((feat_metadata_blk_t*)meta_blk->block)->data_len == ((feat_metadata_blk_t*)deser_blk->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(((feat_metadata_blk_t*)meta_blk->block)->data,
                           ((feat_metadata_blk_t*)deser_blk->block)->data,
                           ((feat_metadata_blk_t*)meta_blk->block)->data_len);

  // clean up
  feat_blk_free(meta_blk);
  feat_blk_free(deser_blk);
}

void test_tag_max() {
  // create an Indexation block
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  feat_block_t* tag_blk = feat_blk_tag_new(tag, sizeof(tag));
  TEST_ASSERT_NOT_NULL(tag_blk);
  feat_blk_print(tag_blk);

  // validate object
  TEST_ASSERT(tag_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)tag_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(tag, ((feat_tag_blk_t*)tag_blk->block)->tag, sizeof(tag));

  // serialization
  byte_t serialized_blk[96] = {};
  size_t serialize_len = feat_blk_serialize_len(tag_blk);
  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(tag_blk, serialized_blk, 1) == 0);
  // should equal to serialize_len
  TEST_ASSERT(feat_blk_serialize(tag_blk, serialized_blk, sizeof(serialized_blk)) == serialize_len);

  // expect deserialize failed
  TEST_ASSERT_NULL(feat_blk_deserialize(serialized_blk, serialize_len - 1));

  // should create a tag block
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate serialization
  TEST_ASSERT(tag_blk->type == deser_blk->type);
  TEST_ASSERT(((feat_tag_blk_t*)tag_blk->block)->tag_len == ((feat_tag_blk_t*)deser_blk->block)->tag_len);
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)tag_blk->block)->tag, ((feat_tag_blk_t*)deser_blk->block)->tag,
                           ((feat_tag_blk_t*)tag_blk->block)->tag_len);

  // clean up
  feat_blk_free(tag_blk);
  feat_blk_free(deser_blk);
}

void test_tag_one_byte() {
  byte_t tag = 'T';
  feat_block_t* tag_blk = feat_blk_tag_new(&tag, sizeof(tag));
  TEST_ASSERT_NOT_NULL(tag_blk);
  feat_blk_print(tag_blk);

  // validate object
  TEST_ASSERT(tag_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)tag_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(&tag, ((feat_tag_blk_t*)tag_blk->block)->tag, sizeof(tag));

  // serialization
  byte_t serialized_blk[16] = {};
  size_t serialize_len = feat_blk_serialize_len(tag_blk);
  // expect serialization failed
  TEST_ASSERT(feat_blk_serialize(tag_blk, serialized_blk, sizeof(tag)) == 0);
  TEST_ASSERT(feat_blk_serialize(tag_blk, serialized_blk, sizeof(serialized_blk)) == serialize_len);
  // deserialize
  TEST_ASSERT_NULL(feat_blk_deserialize(serialized_blk, serialize_len - 1));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, serialize_len);
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(tag_blk->type == deser_blk->type);
  TEST_ASSERT(((feat_tag_blk_t*)tag_blk->block)->tag_len == ((feat_tag_blk_t*)deser_blk->block)->tag_len);
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)tag_blk->block)->tag, ((feat_tag_blk_t*)deser_blk->block)->tag,
                           ((feat_tag_blk_t*)tag_blk->block)->tag_len);

  // clean up
  feat_blk_free(tag_blk);
  feat_blk_free(deser_blk);
}

void test_feat_block_list_append_all() {
  feat_blk_list_t* blk_list = feat_blk_list_new();
  TEST_ASSERT_NULL(blk_list);

  // print out an empty list
  feat_blk_list_print(blk_list, false, 0);

  // add a sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_PUBKEY_HASH_BYTES);
  TEST_ASSERT(feat_blk_list_add_sender(&blk_list, &test_addr) == 0);
  // adding 2nd sender should be failed
  TEST_ASSERT(feat_blk_list_add_sender(&blk_list, &test_addr) != 0);

  // add an issuer, changed the type, but use the same address data
  test_addr.type = ADDRESS_TYPE_NFT;
  TEST_ASSERT(feat_blk_list_add_issuer(&blk_list, &test_addr) == 0);
  // adding 2nd issuer should be failed
  TEST_ASSERT(feat_blk_list_add_issuer(&blk_list, &test_addr) != 0);

  // add a metadata
  byte_t meta_data[80] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  TEST_ASSERT(feat_blk_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) == 0);
  // adding 2nd metadata should be failed
  TEST_ASSERT(feat_blk_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) != 0);

  // add an indexation tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feat_blk_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);
  // adding 2nd tag should be failed
  TEST_ASSERT(feat_blk_list_add_tag(&blk_list, tag, sizeof(tag)) != 0);

  // check length of the list
  TEST_ASSERT(feat_blk_list_len(blk_list) == 4);

  // print out the feature block list
  feat_blk_list_print(blk_list, false, 0);

  // cannot add more block, the MAX block in a list is 4(MAX_FEATURE_BLOCK_COUNT)
  TEST_ASSERT(feat_blk_list_add_sender(&blk_list, &test_addr) != 0);
  TEST_ASSERT(feat_blk_list_add_issuer(&blk_list, &test_addr) != 0);
  TEST_ASSERT(feat_blk_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) != 0);
  TEST_ASSERT(feat_blk_list_add_tag(&blk_list, tag, sizeof(tag)) != 0);

  // serialization
  size_t exp_ser_len = feat_blk_list_serialize_len(blk_list);
  // printf("serialization len: %zu\n", exp_ser_len);
  byte_t ser_blk[512] = {};
  TEST_ASSERT(feat_blk_list_serialize(&blk_list, ser_blk, sizeof(ser_blk)) == exp_ser_len);
  // dump_hex(ser_blk, exp_ser_len);
  feat_blk_list_t* deser_list = feat_blk_list_deserialize(ser_blk, sizeof(ser_blk));
  TEST_ASSERT(feat_blk_list_len(deser_list) == feat_blk_list_len(blk_list));
  feat_blk_list_print(deser_list, false, 0);

  // check deserialized data
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, feat_blk_list_len(deser_list)));
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, MAX_FEATURE_BLOCK_COUNT));
  feat_block_t* tmp_blk = NULL;

  // 0: should be Sender
  tmp_blk = feat_blk_list_get(deser_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_PUBKEY_HASH_BYTES);

  // 1: should be Issuer
  tmp_blk = feat_blk_list_get(deser_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, NFT_ID_BYTES);

  // 2: should be Metadata
  tmp_blk = feat_blk_list_get(deser_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)tmp_blk->block)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feat_metadata_blk_t*)tmp_blk->block)->data, meta_data, sizeof(meta_data));

  // 3: should be Tag
  tmp_blk = feat_blk_list_get(deser_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)tmp_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)tmp_blk->block)->tag, tag, sizeof(tag));

  // clean up
  feat_blk_list_free(deser_list);
  feat_blk_list_free(blk_list);
}

void test_feat_block_list_sort() {
  feat_blk_list_t* blk_list = feat_blk_list_new();
  TEST_ASSERT_NULL(blk_list);

  // print out an empty list
  feat_blk_list_print(blk_list, false, 0);

  // add feature blocks in "random" order
  // add a Tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feat_blk_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);
  // add a Sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_PUBKEY_HASH_BYTES);
  TEST_ASSERT(feat_blk_list_add_sender(&blk_list, &test_addr) == 0);
  // add a Metadata
  byte_t meta_data[256] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  TEST_ASSERT(feat_blk_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) == 0);
  // add an Issuer
  test_addr.type = ADDRESS_TYPE_NFT;  // changed the type, but use the same address data
  TEST_ASSERT(feat_blk_list_add_issuer(&blk_list, &test_addr) == 0);

  // check length of the list
  TEST_ASSERT(feat_blk_list_len(blk_list) == 4);
  feat_block_t* tmp_blk = NULL;

  // feature blocks should NOT be in ascending order based on block type
  // 0: should be Tag
  tmp_blk = feat_blk_list_get(blk_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)tmp_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)tmp_blk->block)->tag, tag, sizeof(tag));

  // 1: should be Sender
  tmp_blk = feat_blk_list_get(blk_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_PUBKEY_HASH_BYTES);

  // 2: should be metadata
  tmp_blk = feat_blk_list_get(blk_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)tmp_blk->block)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feat_metadata_blk_t*)tmp_blk->block)->data, meta_data, sizeof(meta_data));

  // 3: should be Issuer
  tmp_blk = feat_blk_list_get(blk_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, NFT_ID_BYTES);

  // 4: should be NULL
  tmp_blk = feat_blk_list_get(blk_list, 4);
  TEST_ASSERT_NULL(tmp_blk);

  // print out the feature block list
  feat_blk_list_print(blk_list, false, 0);

  // serialization
  size_t exp_ser_len = feat_blk_list_serialize_len(blk_list);
  // printf("serialization len: %zu\n", exp_ser_len);
  byte_t ser_blk[512] = {};
  TEST_ASSERT(feat_blk_list_serialize(&blk_list, ser_blk, sizeof(ser_blk)) == exp_ser_len);
  // dump_hex(ser_blk, exp_ser_len);
  feat_blk_list_t* deser_list = feat_blk_list_deserialize(ser_blk, sizeof(ser_blk));
  TEST_ASSERT(feat_blk_list_len(deser_list) == feat_blk_list_len(blk_list));
  feat_blk_list_print(deser_list, false, 0);

  // check deser objects
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, feat_blk_list_len(deser_list)));
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, UINT8_MAX - 1));

  // feature blocks should be in ascending order based on block type
  // 0: should be Sender
  tmp_blk = feat_blk_list_get(deser_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_PUBKEY_HASH_BYTES);

  // 1: should be Issuer
  tmp_blk = feat_blk_list_get(deser_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, NFT_ID_BYTES);

  // 2: should be Metadata
  tmp_blk = feat_blk_list_get(deser_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)tmp_blk->block)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feat_metadata_blk_t*)tmp_blk->block)->data, meta_data, sizeof(meta_data));

  // 3: should be Tag
  tmp_blk = feat_blk_list_get(deser_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)tmp_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)tmp_blk->block)->tag, tag, sizeof(tag));

  // 4: should be NULL
  tmp_blk = feat_blk_list_get(deser_list, 4);
  TEST_ASSERT_NULL(tmp_blk);

  // clean up
  feat_blk_list_free(deser_list);
  feat_blk_list_free(blk_list);
}

void test_feat_block_list_clone() {
  //=====NULL feature block list=====
  feat_blk_list_t* new_blk_list = feat_blk_list_clone(NULL);
  TEST_ASSERT_NULL(new_blk_list);

  //=====Test feature block list object=====
  feat_blk_list_t* blk_list = feat_blk_list_new();

  // add a Sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_PUBKEY_HASH_BYTES);
  TEST_ASSERT(feat_blk_list_add_sender(&blk_list, &test_addr) == 0);
  // add an Issuer
  test_addr.type = ADDRESS_TYPE_NFT;  // changed the type, but use the same address data
  TEST_ASSERT(feat_blk_list_add_issuer(&blk_list, &test_addr) == 0);
  // add a Metadata
  byte_t meta_data[256] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  TEST_ASSERT(feat_blk_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) == 0);
  // add a Tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feat_blk_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);

  // check length of the list
  TEST_ASSERT(feat_blk_list_len(blk_list) == 4);

  // print out the feature block list
  feat_blk_list_print(blk_list, false, 0);

  // clone feature block list
  new_blk_list = feat_blk_list_clone(blk_list);

  // check new cloned feature block list
  feat_block_t* tmp_blk = NULL;

  // check length of the new feature block list
  TEST_ASSERT(feat_blk_list_len(new_blk_list) == 4);

  // 0: should be Sender
  tmp_blk = feat_blk_list_get(new_blk_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_PUBKEY_HASH_BYTES);

  // 1: should be Issuer
  tmp_blk = feat_blk_list_get(new_blk_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, NFT_ID_BYTES);

  // 2: should be Metadata
  tmp_blk = feat_blk_list_get(new_blk_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)tmp_blk->block)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feat_metadata_blk_t*)tmp_blk->block)->data, meta_data, sizeof(meta_data));

  // 3: should be Tag
  tmp_blk = feat_blk_list_get(new_blk_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)tmp_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)tmp_blk->block)->tag, tag, sizeof(tag));

  // clean up
  feat_blk_list_free(new_blk_list);
  feat_blk_list_free(blk_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_sender);
  RUN_TEST(test_issuer);
  RUN_TEST(test_metadata_max);
  RUN_TEST(test_metadata_one_byte);
  RUN_TEST(test_tag_max);
  RUN_TEST(test_tag_one_byte);
  RUN_TEST(test_feat_block_list_append_all);
  RUN_TEST(test_feat_block_list_sort);
  RUN_TEST(test_feat_block_list_clone);

  return UNITY_END();
}
