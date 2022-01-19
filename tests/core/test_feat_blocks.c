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
  byte_t serialized_blk[64] = {};

  // create a Sender feature block
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ADDRESS_ED25519_BYTES);
  feat_block_t* sender_blk = new_feat_blk_sender(&sender_addr);
  TEST_ASSERT_NOT_NULL(sender_blk);
  feat_blk_print(sender_blk);

  // validate sender object
  TEST_ASSERT(sender_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)sender_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)sender_blk->block)->address, sender_addr.address, ADDRESS_ED25519_BYTES);

  // serialization
  TEST_ASSERT(feat_blk_serialize(sender_blk, serialized_blk, 1) == 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(sender_blk, serialized_blk, sizeof(serialized_blk)) ==
              feat_blk_serialize_len(sender_blk));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(sender_blk->type == deser_blk->type);
  TEST_ASSERT(((address_t*)sender_blk->block)->type == ((address_t*)deser_blk->block)->type);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)sender_blk->block)->address, ((address_t*)deser_blk->block)->address,
                           address_len((address_t*)sender_blk->block));

  // clean up
  free_feat_blk(sender_blk);
  free_feat_blk(deser_blk);
}

void test_issuer() {
  byte_t serialized_blk[64] = {};

  // create an Issuer feature block
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, ADDRESS_NFT_BYTES);
  feat_block_t* issuer_blk = new_feat_blk_issuer(&addr);
  TEST_ASSERT_NOT_NULL(issuer_blk);
  feat_blk_print(issuer_blk);

  // validate issuer object
  TEST_ASSERT(issuer_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)issuer_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)issuer_blk->block)->address, addr.address, ADDRESS_NFT_BYTES);

  // serialization
  TEST_ASSERT(feat_blk_serialize(issuer_blk, serialized_blk, 1) == 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(issuer_blk, serialized_blk, sizeof(serialized_blk)) ==
              feat_blk_serialize_len(issuer_blk));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate serialization
  TEST_ASSERT(issuer_blk->type == deser_blk->type);
  TEST_ASSERT(((address_t*)issuer_blk->block)->type == ((address_t*)deser_blk->block)->type);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)issuer_blk->block)->address, ((address_t*)deser_blk->block)->address,
                           address_len((address_t*)issuer_blk->block));

  // clean up
  free_feat_blk(issuer_blk);
  free_feat_blk(deser_blk);
}

void test_metadata() {
  byte_t serialized_blk[160] = {};

  // create a Metadata block
  byte_t meta_data[128] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  feat_block_t* meta_blk = new_feat_blk_metadata(meta_data, sizeof(meta_data));
  TEST_ASSERT_NOT_NULL(meta_blk);
  feat_blk_print(meta_blk);

  // validate object
  TEST_ASSERT(meta_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)meta_blk->block)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(meta_data, ((feat_metadata_blk_t*)meta_blk->block)->data, sizeof(meta_data));

  // serialization
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, 1) == 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, sizeof(serialized_blk)) == feat_blk_serialize_len(meta_blk));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, feat_blk_serialize_len(meta_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(meta_blk->type == deser_blk->type);
  TEST_ASSERT(((feat_metadata_blk_t*)meta_blk->block)->data_len == ((feat_metadata_blk_t*)deser_blk->block)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(((feat_metadata_blk_t*)meta_blk->block)->data,
                           ((feat_metadata_blk_t*)deser_blk->block)->data,
                           ((feat_metadata_blk_t*)meta_blk->block)->data_len);

  // clean up
  free_feat_blk(meta_blk);
  free_feat_blk(deser_blk);
}

void test_tag() {
  byte_t serialized_blk[96] = {};

  // create an Indexation block
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));

  feat_block_t* idx_blk = new_feat_blk_tag(tag, sizeof(tag));
  TEST_ASSERT_NOT_NULL(idx_blk);
  feat_blk_print(idx_blk);

  // validate object
  TEST_ASSERT(idx_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)idx_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(tag, ((feat_tag_blk_t*)idx_blk->block)->tag, sizeof(tag));

  // serialization
  TEST_ASSERT(feat_blk_serialize(idx_blk, serialized_blk, 1) == 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(idx_blk, serialized_blk, sizeof(serialized_blk)) == feat_blk_serialize_len(idx_blk));
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, feat_blk_serialize_len(idx_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(idx_blk->type == deser_blk->type);
  TEST_ASSERT(((feat_tag_blk_t*)idx_blk->block)->tag_len == ((feat_tag_blk_t*)deser_blk->block)->tag_len);
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)idx_blk->block)->tag, ((feat_tag_blk_t*)deser_blk->block)->tag,
                           ((feat_tag_blk_t*)idx_blk->block)->tag_len);

  // clean up
  free_feat_blk(idx_blk);
  free_feat_blk(deser_blk);
}

void test_feat_block_list_append_all() {
  feat_blk_list_t* blk_list = new_feat_blk_list();
  TEST_ASSERT_NULL(blk_list);

  // print out an empty list
  feat_blk_list_print(blk_list, 0);

  // add a sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT(feat_blk_list_add_sender(&blk_list, &test_addr) == 0);

  // add an issuer
  test_addr.type = ADDRESS_TYPE_NFT;  // changed the type, but use the same address data
  TEST_ASSERT(feat_blk_list_add_issuer(&blk_list, &test_addr) == 0);
  // add a metadata
  byte_t meta_data[256] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  TEST_ASSERT(feat_blk_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) == 0);
  // add an indexation tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feat_blk_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);

  // check length of the list
  TEST_ASSERT(feat_blk_list_len(blk_list) == 4);

  // print out the feature block list
  feat_blk_list_print(blk_list, 0);

  // serialization
  size_t exp_ser_len = feat_blk_list_serialize_len(blk_list);
  // printf("serialization len: %zu\n", exp_ser_len);
  byte_t ser_blk[512] = {};
  TEST_ASSERT(feat_blk_list_serialize(blk_list, ser_blk, sizeof(ser_blk)) == exp_ser_len);
  // dump_hex(ser_blk, exp_ser_len);
  feat_blk_list_t* deser_list = feat_blk_list_deserialize(ser_blk, sizeof(ser_blk));
  TEST_ASSERT(feat_blk_list_len(deser_list) == feat_blk_list_len(blk_list));
  feat_blk_list_print(deser_list, 0);

  // check deser objects
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, feat_blk_list_len(deser_list)));
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, UINT8_MAX - 1));
  feat_block_t* tmp_blk = NULL;

  // 0: should be Sender
  tmp_blk = feat_blk_list_get(deser_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_ED25519_BYTES);

  // 1: should be Issuer
  tmp_blk = feat_blk_list_get(deser_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_NFT_BYTES);

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
  free_feat_blk_list(deser_list);
  free_feat_blk_list(blk_list);
}

void test_feat_block_list_sort() {
  feat_blk_list_t* blk_list = new_feat_blk_list();
  TEST_ASSERT_NULL(blk_list);

  // print out an empty list
  feat_blk_list_print(blk_list, 0);

  // add feature blocks in "random" order
  // add a Sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT(feat_blk_list_add_sender(&blk_list, &test_addr) == 0);
  // add a Tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feat_blk_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);
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
  // 0: should be Sender
  tmp_blk = feat_blk_list_get(blk_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_ED25519_BYTES);

  // 1: should be Tag
  tmp_blk = feat_blk_list_get(blk_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_BLOCK);
  TEST_ASSERT(((feat_tag_blk_t*)tmp_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feat_tag_blk_t*)tmp_blk->block)->tag, tag, sizeof(tag));

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
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_NFT_BYTES);

  // 4: should be NULL
  tmp_blk = feat_blk_list_get(blk_list, 4);
  TEST_ASSERT_NULL(tmp_blk);

  // print out the feature block list
  feat_blk_list_print(blk_list, 0);

  // serialization
  size_t exp_ser_len = feat_blk_list_serialize_len(blk_list);
  // printf("serialization len: %zu\n", exp_ser_len);
  byte_t ser_blk[512] = {};
  TEST_ASSERT(feat_blk_list_serialize(blk_list, ser_blk, sizeof(ser_blk)) == exp_ser_len);
  // dump_hex(ser_blk, exp_ser_len);
  feat_blk_list_t* deser_list = feat_blk_list_deserialize(ser_blk, sizeof(ser_blk));
  TEST_ASSERT(feat_blk_list_len(deser_list) == feat_blk_list_len(blk_list));
  feat_blk_list_print(deser_list, 0);

  // check deser objects
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, feat_blk_list_len(deser_list)));
  TEST_ASSERT_NULL(feat_blk_list_get(deser_list, UINT8_MAX - 1));

  // feature blocks should be in ascending order based on block type
  // 0: should be Sender
  tmp_blk = feat_blk_list_get(deser_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_ED25519_BYTES);

  // 1: should be Issuer
  tmp_blk = feat_blk_list_get(deser_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_NFT_BYTES);

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
  free_feat_blk_list(deser_list);
  free_feat_blk_list(blk_list);
}

void test_feat_block_list_clone() {
  //=====NULL feature block list=====
  feat_blk_list_t* new_blk_list = feat_blk_list_clone(NULL);
  TEST_ASSERT_NULL(new_blk_list);

  //=====Test feature block list object=====
  feat_blk_list_t* blk_list = new_feat_blk_list();

  // add a Sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ADDRESS_ED25519_BYTES);
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
  feat_blk_list_print(blk_list, 0);

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
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_ED25519_BYTES);

  // 1: should be Issuer
  tmp_blk = feat_blk_list_get(new_blk_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)tmp_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->block)->address, test_addr.address, ADDRESS_NFT_BYTES);

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
  free_feat_blk_list(new_blk_list);
  free_feat_blk_list(blk_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_sender);
  RUN_TEST(test_issuer);
  RUN_TEST(test_metadata);
  RUN_TEST(test_tag);
  RUN_TEST(test_feat_block_list_append_all);
  RUN_TEST(test_feat_block_list_sort);
  RUN_TEST(test_feat_block_list_clone);

  return UNITY_END();
}
