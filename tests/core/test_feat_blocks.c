// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/constants.h"
#include "core/models/outputs/feat_blocks.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_sender() {
  // create a Sender feature
  address_t sender_addr = {};
  sender_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(sender_addr.address, ED25519_PUBKEY_BYTES);
  output_feature_t* sender_feat = feature_sender_new(&sender_addr);
  TEST_ASSERT_NOT_NULL(sender_feat);
  feature_print(sender_feat);

  // validate sender object
  TEST_ASSERT(sender_feat->type == FEAT_SENDER_TYPE);
  TEST_ASSERT_TRUE(address_equal((address_t*)sender_feat->obj, &sender_addr));

  // serialization
  byte_t serialized_feat[64] = {};
  size_t serialized_len = feature_serialize_len(sender_feat);
  // expect serialize failed
  TEST_ASSERT(feature_serialize(sender_feat, serialized_feat, 1) == 0);
  TEST_ASSERT(feature_serialize(sender_feat, serialized_feat, sizeof(serialized_feat)) == serialized_len);
  // expect deserialize failed
  TEST_ASSERT_NULL(feature_deserialize(serialized_feat, serialized_len - 1));
  output_feature_t* deser_feat = feature_deserialize(serialized_feat, sizeof(serialized_feat));
  TEST_ASSERT_NOT_NULL(deser_feat);

  // validate feature type
  TEST_ASSERT(sender_feat->type == deser_feat->type);
  // validate address
  TEST_ASSERT_TRUE(address_equal((address_t*)sender_feat->obj, (address_t*)deser_feat->obj));

  // clean up
  feature_free(sender_feat);
  feature_free(deser_feat);
}

void test_issuer() {
  // create an Issuer feature
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, NFT_ID_BYTES);
  output_feature_t* issuer_blk = feature_issuer_new(&addr);
  TEST_ASSERT_NOT_NULL(issuer_blk);
  feature_print(issuer_blk);

  // validate issuer object
  TEST_ASSERT(issuer_blk->type == FEAT_ISSUER_TYPE);
  TEST_ASSERT_TRUE(address_equal((address_t*)issuer_blk->obj, &addr));

  // serialization
  byte_t serialized_feat[64] = {};
  size_t serialized_len = feature_serialize_len(issuer_blk);
  TEST_ASSERT(feature_serialize(issuer_blk, serialized_feat, 1) == 0);  // expect serialize failed
  TEST_ASSERT(feature_serialize(issuer_blk, serialized_feat, sizeof(serialized_feat)) == serialized_len);
  // expect deserialize failed
  TEST_ASSERT_NULL(feature_deserialize(serialized_feat, serialized_len - 1));
  output_feature_t* deser_feat = feature_deserialize(serialized_feat, sizeof(serialized_feat));
  TEST_ASSERT_NOT_NULL(deser_feat);

  // validate feature type
  TEST_ASSERT(issuer_blk->type == deser_feat->type);
  // validate address
  TEST_ASSERT_TRUE(address_equal((address_t*)issuer_blk->obj, (address_t*)deser_feat->obj));

  // clean up
  feature_free(issuer_blk);
  feature_free(deser_feat);
}

void test_metadata_max() {
  // create a Metadata feature
  byte_t meta_data[MAX_METADATA_LENGTH_BYTES] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  // metadata must smaller than MAX_METADATA_LENGTH_BYTES
  TEST_ASSERT_NULL(feature_metadata_new(meta_data, sizeof(meta_data) + 1));

  // metadata with MAX_METADATA_LENGTH_BYTES
  output_feature_t* meta_feat = feature_metadata_new(meta_data, sizeof(meta_data));
  TEST_ASSERT_NOT_NULL(meta_feat);
  feature_print(meta_feat);

  // validate object
  TEST_ASSERT(meta_feat->type == FEAT_METADATA_TYPE);
  TEST_ASSERT(((feature_metadata_t*)meta_feat->obj)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(meta_data, ((feature_metadata_t*)meta_feat->obj)->data, sizeof(meta_data));

  // serialization
  size_t serialize_len = feature_serialize_len(meta_feat);
  byte_t* serialized_feat = malloc(serialize_len);
  TEST_ASSERT_NOT_NULL(serialized_feat);
  // expect serialization failed
  TEST_ASSERT(feature_serialize(meta_feat, serialized_feat, sizeof(meta_data)) == 0);
  TEST_ASSERT(feature_serialize(meta_feat, serialized_feat, serialize_len) == serialize_len);
  // deserialize
  TEST_ASSERT_NULL(feature_deserialize(serialized_feat, serialize_len - 1));
  output_feature_t* deser_feat = feature_deserialize(serialized_feat, serialize_len);
  TEST_ASSERT_NOT_NULL(deser_feat);

  // validate
  TEST_ASSERT(meta_feat->type == deser_feat->type);
  TEST_ASSERT(((feature_metadata_t*)meta_feat->obj)->data_len == ((feature_metadata_t*)deser_feat->obj)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(((feature_metadata_t*)meta_feat->obj)->data, ((feature_metadata_t*)deser_feat->obj)->data,
                           ((feature_metadata_t*)meta_feat->obj)->data_len);

  // clean up
  free(serialized_feat);
  feature_free(meta_feat);
  feature_free(deser_feat);
}

void test_metadata_one_byte() {
  byte_t meta = 'A';
  output_feature_t* meta_feat = feature_metadata_new(&meta, sizeof(meta));
  TEST_ASSERT_NOT_NULL(meta_feat);
  feature_print(meta_feat);

  // validate object
  TEST_ASSERT(meta_feat->type == FEAT_METADATA_TYPE);
  TEST_ASSERT(((feature_metadata_t*)meta_feat->obj)->data_len == sizeof(meta));
  TEST_ASSERT_EQUAL_MEMORY(&meta, ((feature_metadata_t*)meta_feat->obj)->data, sizeof(meta));

  // serialization
  byte_t serialized_feat[32] = {};
  size_t serialize_len = feature_serialize_len(meta_feat);
  // expect serialization failed
  TEST_ASSERT(feature_serialize(meta_feat, serialized_feat, sizeof(meta)) == 0);
  TEST_ASSERT(feature_serialize(meta_feat, serialized_feat, sizeof(serialized_feat)) == serialize_len);
  // deserialize
  TEST_ASSERT_NULL(feature_deserialize(serialized_feat, serialize_len - 1));
  output_feature_t* deser_feat = feature_deserialize(serialized_feat, serialize_len);
  TEST_ASSERT_NOT_NULL(deser_feat);

  // validate
  TEST_ASSERT(meta_feat->type == deser_feat->type);
  TEST_ASSERT(((feature_metadata_t*)meta_feat->obj)->data_len == ((feature_metadata_t*)deser_feat->obj)->data_len);
  TEST_ASSERT_EQUAL_MEMORY(((feature_metadata_t*)meta_feat->obj)->data, ((feature_metadata_t*)deser_feat->obj)->data,
                           ((feature_metadata_t*)meta_feat->obj)->data_len);

  // clean up
  feature_free(meta_feat);
  feature_free(deser_feat);
}

void test_tag_max() {
  // create a Tag Feature
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  output_feature_t* tag_blk = feature_tag_new(tag, sizeof(tag));
  TEST_ASSERT_NOT_NULL(tag_blk);
  feature_print(tag_blk);

  // validate object
  TEST_ASSERT(tag_blk->type == FEAT_TAG_TYPE);
  TEST_ASSERT(((feature_tag_t*)tag_blk->obj)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(tag, ((feature_tag_t*)tag_blk->obj)->tag, sizeof(tag));

  // serialization
  byte_t serialized_feat[96] = {};
  size_t serialize_len = feature_serialize_len(tag_blk);
  // expect serialize failed
  TEST_ASSERT(feature_serialize(tag_blk, serialized_feat, 1) == 0);
  // should equal to serialize_len
  TEST_ASSERT(feature_serialize(tag_blk, serialized_feat, sizeof(serialized_feat)) == serialize_len);

  // expect deserialize failed
  TEST_ASSERT_NULL(feature_deserialize(serialized_feat, serialize_len - 1));

  // should create a tag feature
  output_feature_t* deser_feat = feature_deserialize(serialized_feat, sizeof(serialized_feat));
  TEST_ASSERT_NOT_NULL(deser_feat);

  // validate serialization
  TEST_ASSERT(tag_blk->type == deser_feat->type);
  TEST_ASSERT(((feature_tag_t*)tag_blk->obj)->tag_len == ((feature_tag_t*)deser_feat->obj)->tag_len);
  TEST_ASSERT_EQUAL_MEMORY(((feature_tag_t*)tag_blk->obj)->tag, ((feature_tag_t*)deser_feat->obj)->tag,
                           ((feature_tag_t*)tag_blk->obj)->tag_len);

  // clean up
  feature_free(tag_blk);
  feature_free(deser_feat);
}

void test_tag_one_byte() {
  byte_t tag = 'T';
  output_feature_t* tag_blk = feature_tag_new(&tag, sizeof(tag));
  TEST_ASSERT_NOT_NULL(tag_blk);
  feature_print(tag_blk);

  // validate object
  TEST_ASSERT(tag_blk->type == FEAT_TAG_TYPE);
  TEST_ASSERT(((feature_tag_t*)tag_blk->obj)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(&tag, ((feature_tag_t*)tag_blk->obj)->tag, sizeof(tag));

  // serialization
  byte_t serialized_feat[16] = {};
  size_t serialize_len = feature_serialize_len(tag_blk);
  // expect serialization failed
  TEST_ASSERT(feature_serialize(tag_blk, serialized_feat, sizeof(tag)) == 0);
  TEST_ASSERT(feature_serialize(tag_blk, serialized_feat, sizeof(serialized_feat)) == serialize_len);
  // deserialize
  TEST_ASSERT_NULL(feature_deserialize(serialized_feat, serialize_len - 1));
  output_feature_t* deser_feat = feature_deserialize(serialized_feat, serialize_len);
  TEST_ASSERT_NOT_NULL(deser_feat);

  // validate
  TEST_ASSERT(tag_blk->type == deser_feat->type);
  TEST_ASSERT(((feature_tag_t*)tag_blk->obj)->tag_len == ((feature_tag_t*)deser_feat->obj)->tag_len);
  TEST_ASSERT_EQUAL_MEMORY(((feature_tag_t*)tag_blk->obj)->tag, ((feature_tag_t*)deser_feat->obj)->tag,
                           ((feature_tag_t*)tag_blk->obj)->tag_len);

  // clean up
  feature_free(tag_blk);
  feature_free(deser_feat);
}

void test_feature_list_append_all() {
  feature_list_t* blk_list = feature_list_new();
  TEST_ASSERT_NULL(blk_list);

  // print out an empty list
  feature_list_print(blk_list, false, 0);

  // add a sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT(feature_list_add_sender(&blk_list, &test_addr) == 0);
  // adding 2nd sender should be failed
  TEST_ASSERT(feature_list_add_sender(&blk_list, &test_addr) != 0);

  // add an issuer, changed the type, but use the same address data
  test_addr.type = ADDRESS_TYPE_NFT;
  TEST_ASSERT(feature_list_add_issuer(&blk_list, &test_addr) == 0);
  // adding 2nd issuer should be failed
  TEST_ASSERT(feature_list_add_issuer(&blk_list, &test_addr) != 0);

  // add a metadata
  byte_t meta_data[80] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  TEST_ASSERT(feature_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) == 0);
  // adding 2nd metadata should be failed
  TEST_ASSERT(feature_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) != 0);

  // add an indexation tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feature_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);
  // adding 2nd tag should be failed
  TEST_ASSERT(feature_list_add_tag(&blk_list, tag, sizeof(tag)) != 0);

  // check length of the list
  TEST_ASSERT(feature_list_len(blk_list) == 4);

  // print out the feature list
  feature_list_print(blk_list, false, 0);

  // cannot add more features, the MAX feature in a list is 4(MAX_FEATURE_BLOCK_COUNT)
  TEST_ASSERT(feature_list_add_sender(&blk_list, &test_addr) != 0);
  TEST_ASSERT(feature_list_add_issuer(&blk_list, &test_addr) != 0);
  TEST_ASSERT(feature_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) != 0);
  TEST_ASSERT(feature_list_add_tag(&blk_list, tag, sizeof(tag)) != 0);

  // serialization
  size_t exp_ser_len = feature_list_serialize_len(blk_list);
  // printf("serialization len: %zu\n", exp_ser_len);
  byte_t ser_blk[512] = {};
  TEST_ASSERT(feature_list_serialize(&blk_list, ser_blk, sizeof(ser_blk)) == exp_ser_len);
  // dump_hex(ser_blk, exp_ser_len);
  feature_list_t* deser_list = feature_list_deserialize(ser_blk, sizeof(ser_blk));
  TEST_ASSERT(feature_list_len(deser_list) == feature_list_len(blk_list));
  feature_list_print(deser_list, false, 0);

  // check deserialized data
  TEST_ASSERT_NULL(feature_list_get(deser_list, feature_list_len(deser_list)));
  TEST_ASSERT_NULL(feature_list_get(deser_list, MAX_FEATURE_BLOCK_COUNT));
  output_feature_t* tmp_blk = NULL;

  // 0: should be Sender
  tmp_blk = feature_list_get(deser_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, ED25519_PUBKEY_BYTES);

  // 1: should be Issuer
  tmp_blk = feature_list_get(deser_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, NFT_ID_BYTES);

  // 2: should be Metadata
  tmp_blk = feature_list_get(deser_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_TYPE);
  TEST_ASSERT(((feature_metadata_t*)tmp_blk->obj)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feature_metadata_t*)tmp_blk->obj)->data, meta_data, sizeof(meta_data));

  // 3: should be Tag
  tmp_blk = feature_list_get(deser_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_TYPE);
  TEST_ASSERT(((feature_tag_t*)tmp_blk->obj)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feature_tag_t*)tmp_blk->obj)->tag, tag, sizeof(tag));

  // clean up
  feature_list_free(deser_list);
  feature_list_free(blk_list);
}

void test_feature_list_sort() {
  feature_list_t* blk_list = feature_list_new();
  TEST_ASSERT_NULL(blk_list);

  // print out an empty list
  feature_list_print(blk_list, false, 0);

  // add features in "random" order
  // add a Tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feature_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);
  // add a Sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT(feature_list_add_sender(&blk_list, &test_addr) == 0);
  // add a Metadata
  byte_t meta_data[256] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  TEST_ASSERT(feature_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) == 0);
  // add an Issuer
  test_addr.type = ADDRESS_TYPE_NFT;  // changed the type, but use the same address data
  TEST_ASSERT(feature_list_add_issuer(&blk_list, &test_addr) == 0);

  // check length of the list
  TEST_ASSERT(feature_list_len(blk_list) == 4);
  output_feature_t* tmp_blk = NULL;

  // features should NOT be in ascending order based on feature type
  // 0: should be Tag
  tmp_blk = feature_list_get(blk_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_TYPE);
  TEST_ASSERT(((feature_tag_t*)tmp_blk->obj)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feature_tag_t*)tmp_blk->obj)->tag, tag, sizeof(tag));

  // 1: should be Sender
  tmp_blk = feature_list_get(blk_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, ED25519_PUBKEY_BYTES);

  // 2: should be metadata
  tmp_blk = feature_list_get(blk_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_TYPE);
  TEST_ASSERT(((feature_metadata_t*)tmp_blk->obj)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feature_metadata_t*)tmp_blk->obj)->data, meta_data, sizeof(meta_data));

  // 3: should be Issuer
  tmp_blk = feature_list_get(blk_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, NFT_ID_BYTES);

  // 4: should be NULL
  tmp_blk = feature_list_get(blk_list, 4);
  TEST_ASSERT_NULL(tmp_blk);

  // print out the feature list
  feature_list_print(blk_list, false, 0);

  // serialization
  size_t exp_ser_len = feature_list_serialize_len(blk_list);
  // printf("serialization len: %zu\n", exp_ser_len);
  byte_t ser_blk[512] = {};
  TEST_ASSERT(feature_list_serialize(&blk_list, ser_blk, sizeof(ser_blk)) == exp_ser_len);
  // dump_hex(ser_blk, exp_ser_len);
  feature_list_t* deser_list = feature_list_deserialize(ser_blk, sizeof(ser_blk));
  TEST_ASSERT(feature_list_len(deser_list) == feature_list_len(blk_list));
  feature_list_print(deser_list, false, 0);

  // check deser objects
  TEST_ASSERT_NULL(feature_list_get(deser_list, feature_list_len(deser_list)));
  TEST_ASSERT_NULL(feature_list_get(deser_list, UINT8_MAX - 1));

  // features should be in ascending order based on feature type
  // 0: should be Sender
  tmp_blk = feature_list_get(deser_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, ED25519_PUBKEY_BYTES);

  // 1: should be Issuer
  tmp_blk = feature_list_get(deser_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, NFT_ID_BYTES);

  // 2: should be Metadata
  tmp_blk = feature_list_get(deser_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_TYPE);
  TEST_ASSERT(((feature_metadata_t*)tmp_blk->obj)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feature_metadata_t*)tmp_blk->obj)->data, meta_data, sizeof(meta_data));

  // 3: should be Tag
  tmp_blk = feature_list_get(deser_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_TYPE);
  TEST_ASSERT(((feature_tag_t*)tmp_blk->obj)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feature_tag_t*)tmp_blk->obj)->tag, tag, sizeof(tag));

  // 4: should be NULL
  tmp_blk = feature_list_get(deser_list, 4);
  TEST_ASSERT_NULL(tmp_blk);

  // clean up
  feature_list_free(deser_list);
  feature_list_free(blk_list);
}

void test_feature_list_clone() {
  //=====NULL feature list=====
  feature_list_t* new_blk_list = feature_list_clone(NULL);
  TEST_ASSERT_NULL(new_blk_list);

  //=====Test feature list object=====
  feature_list_t* blk_list = feature_list_new();

  // add a Sender
  address_t test_addr = {};
  test_addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(test_addr.address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT(feature_list_add_sender(&blk_list, &test_addr) == 0);
  // add an Issuer
  test_addr.type = ADDRESS_TYPE_NFT;  // changed the type, but use the same address data
  TEST_ASSERT(feature_list_add_issuer(&blk_list, &test_addr) == 0);
  // add a Metadata
  byte_t meta_data[256] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  TEST_ASSERT(feature_list_add_metadata(&blk_list, meta_data, sizeof(meta_data)) == 0);
  // add a Tag
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));
  TEST_ASSERT(feature_list_add_tag(&blk_list, tag, sizeof(tag)) == 0);

  // check length of the list
  TEST_ASSERT(feature_list_len(blk_list) == 4);

  // print out the feature list
  feature_list_print(blk_list, false, 0);

  // clone feature list
  new_blk_list = feature_list_clone(blk_list);

  // check new cloned feature list
  output_feature_t* tmp_blk = NULL;

  // check length of the new feature list
  TEST_ASSERT(feature_list_len(new_blk_list) == 4);

  // 0: should be Sender
  tmp_blk = feature_list_get(new_blk_list, 0);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_SENDER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, ED25519_PUBKEY_BYTES);

  // 1: should be Issuer
  tmp_blk = feature_list_get(new_blk_list, 1);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_ISSUER_TYPE);
  TEST_ASSERT(((address_t*)tmp_blk->obj)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)tmp_blk->obj)->address, test_addr.address, NFT_ID_BYTES);

  // 2: should be Metadata
  tmp_blk = feature_list_get(new_blk_list, 2);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_METADATA_TYPE);
  TEST_ASSERT(((feature_metadata_t*)tmp_blk->obj)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(((feature_metadata_t*)tmp_blk->obj)->data, meta_data, sizeof(meta_data));

  // 3: should be Tag
  tmp_blk = feature_list_get(new_blk_list, 3);
  TEST_ASSERT_NOT_NULL(tmp_blk);
  TEST_ASSERT(tmp_blk->type == FEAT_TAG_TYPE);
  TEST_ASSERT(((feature_tag_t*)tmp_blk->obj)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(((feature_tag_t*)tmp_blk->obj)->tag, tag, sizeof(tag));

  // clean up
  feature_list_free(new_blk_list);
  feature_list_free(blk_list);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_sender);
  RUN_TEST(test_issuer);
  RUN_TEST(test_metadata_max);
  RUN_TEST(test_metadata_one_byte);
  RUN_TEST(test_tag_max);
  RUN_TEST(test_tag_one_byte);
  RUN_TEST(test_feature_list_append_all);
  RUN_TEST(test_feature_list_sort);
  RUN_TEST(test_feature_list_clone);

  return UNITY_END();
}
