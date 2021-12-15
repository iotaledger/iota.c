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

  // validate sender object
  TEST_ASSERT(sender_blk->type == FEAT_SENDER_BLOCK);
  TEST_ASSERT(((address_t*)sender_blk->block)->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)sender_blk->block)->address, sender_addr.address, ADDRESS_ED25519_BYTES);

  // serialization
  TEST_ASSERT(feat_blk_serialize(sender_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(sender_blk, serialized_blk, sizeof(serialized_blk)) == 0);
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

  // validate issuer object
  TEST_ASSERT(issuer_blk->type == FEAT_ISSUER_BLOCK);
  TEST_ASSERT(((address_t*)issuer_blk->block)->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(((address_t*)issuer_blk->block)->address, addr.address, ADDRESS_NFT_BYTES);

  // serialization
  TEST_ASSERT(feat_blk_serialize(issuer_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(issuer_blk, serialized_blk, sizeof(serialized_blk)) == 0);
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

void test_dust_deposit_return() {
  byte_t serialized_blk[16] = {};

  // create a Dust Deposit Return feature block
  uint64_t amount = UINT64_MAX;
  feat_block_t* ddr_blk = new_feat_blk_ddr(amount);
  TEST_ASSERT_NOT_NULL(ddr_blk);

  // validate object
  TEST_ASSERT(ddr_blk->type == FEAT_DUST_DEP_RET_BLOCK);
  TEST_ASSERT(*((uint64_t*)ddr_blk->block) == amount);

  // serialization
  TEST_ASSERT(feat_blk_serialize(ddr_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(ddr_blk, serialized_blk, sizeof(serialized_blk)) == 0);
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(ddr_blk->type == deser_blk->type);
  TEST_ASSERT(*((uint64_t*)ddr_blk->block) == *((uint64_t*)deser_blk->block));

  // clean up
  free_feat_blk(ddr_blk);
  free_feat_blk(deser_blk);
}

void test_timelock_milestone_index() {
  byte_t serialized_blk[8] = {};

  // create a Timelock Milestone Index block
  uint32_t index = UINT32_MAX;
  feat_block_t* tmi_blk = new_feat_blk_tmi(index);
  TEST_ASSERT_NOT_NULL(tmi_blk);

  // validate object
  TEST_ASSERT(tmi_blk->type == FEAT_TIMELOCK_MS_INDEX_BLOCK);
  TEST_ASSERT(*((uint32_t*)tmi_blk->block) == index);

  // serialization
  TEST_ASSERT(feat_blk_serialize(tmi_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(tmi_blk, serialized_blk, sizeof(serialized_blk)) == 0);
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(tmi_blk->type == deser_blk->type);
  TEST_ASSERT(*((uint32_t*)tmi_blk->block) == *((uint32_t*)deser_blk->block));

  // clean up
  free_feat_blk(tmi_blk);
  free_feat_blk(deser_blk);
}

void test_timelock_unix() {
  byte_t serialized_blk[8] = {};

  // create a Timelock Unix block
  uint32_t time = UINT32_MAX;
  feat_block_t* tu_blk = new_feat_blk_tu(time);
  TEST_ASSERT_NOT_NULL(tu_blk);

  // validate object
  TEST_ASSERT(tu_blk->type == FEAT_TIMELOCK_UNIX_BLOCK);
  TEST_ASSERT(*((uint32_t*)tu_blk->block) == time);

  // serialization
  TEST_ASSERT(feat_blk_serialize(tu_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(tu_blk, serialized_blk, sizeof(serialized_blk)) == 0);
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(tu_blk->type == deser_blk->type);
  TEST_ASSERT(*((uint32_t*)tu_blk->block) == *((uint32_t*)deser_blk->block));

  // clean up
  free_feat_blk(tu_blk);
  free_feat_blk(deser_blk);
}

void test_expiration_milestone_index() {
  byte_t serialized_blk[8] = {};

  // create an Expiration Milestone Index block
  uint32_t index = UINT32_MAX;
  feat_block_t* emi_blk = new_feat_blk_emi(index);
  TEST_ASSERT_NOT_NULL(emi_blk);

  // validate object
  TEST_ASSERT(emi_blk->type == FEAT_EXPIRATION_MS_INDEX_BLOCK);
  TEST_ASSERT(*((uint32_t*)emi_blk->block) == index);

  // serialization
  TEST_ASSERT(feat_blk_serialize(emi_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(emi_blk, serialized_blk, sizeof(serialized_blk)) == 0);
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(emi_blk->type == deser_blk->type);
  TEST_ASSERT(*((uint32_t*)emi_blk->block) == *((uint32_t*)deser_blk->block));

  // clean up
  free_feat_blk(emi_blk);
  free_feat_blk(deser_blk);
}

void test_expiration_unix() {
  byte_t serialized_blk[8] = {};

  // create a Timelock Unix block
  uint32_t time = UINT32_MAX;
  feat_block_t* eu_blk = new_feat_blk_eu(time);
  TEST_ASSERT_NOT_NULL(eu_blk);

  // validate object
  TEST_ASSERT(eu_blk->type == FEAT_EXPIRATION_UNIX_BLOCK);
  TEST_ASSERT(*((uint32_t*)eu_blk->block) == time);

  // serialization
  TEST_ASSERT(feat_blk_serialize(eu_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(eu_blk, serialized_blk, sizeof(serialized_blk)) == 0);
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, sizeof(serialized_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(eu_blk->type == deser_blk->type);
  TEST_ASSERT(*((uint32_t*)eu_blk->block) == *((uint32_t*)deser_blk->block));

  // clean up
  free_feat_blk(eu_blk);
  free_feat_blk(deser_blk);
}

void test_metadata() {
  byte_t serialized_blk[160] = {};

  // create a Metadata block
  byte_t meta_data[128] = {};
  iota_crypto_randombytes(meta_data, sizeof(meta_data));
  feat_block_t* meta_blk = new_feat_blk_metadata(meta_data, sizeof(meta_data));
  TEST_ASSERT_NOT_NULL(meta_blk);

  // validate object
  TEST_ASSERT(meta_blk->type == FEAT_METADATA_BLOCK);
  TEST_ASSERT(((feat_metadata_blk_t*)meta_blk->block)->data_len == sizeof(meta_data));
  TEST_ASSERT_EQUAL_MEMORY(meta_data, ((feat_metadata_blk_t*)meta_blk->block)->data, sizeof(meta_data));

  // serialization
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(meta_blk, serialized_blk, sizeof(serialized_blk)) == 0);
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

void test_indexaction() {
  byte_t serialized_blk[96] = {};

  // create a Indexaction block
  byte_t tag[MAX_INDEX_TAG_BYTES] = {};
  iota_crypto_randombytes(tag, sizeof(tag));

  feat_block_t* idx_blk = new_feat_blk_indexaction(tag, sizeof(tag));
  TEST_ASSERT_NOT_NULL(idx_blk);

  // validate object
  TEST_ASSERT(idx_blk->type == FEAT_INDEXATION_BLOCK);
  TEST_ASSERT(((feat_indexaction_blk_t*)idx_blk->block)->tag_len == sizeof(tag));
  TEST_ASSERT_EQUAL_MEMORY(tag, ((feat_indexaction_blk_t*)idx_blk->block)->tag, sizeof(tag));

  // serialization
  TEST_ASSERT(feat_blk_serialize(idx_blk, serialized_blk, 1) != 0);  // expect serialize failed
  TEST_ASSERT(feat_blk_serialize(idx_blk, serialized_blk, sizeof(serialized_blk)) == 0);
  feat_block_t* deser_blk = feat_blk_deserialize(serialized_blk, 1);
  TEST_ASSERT_NULL(deser_blk);  // expect deserialize failed
  deser_blk = feat_blk_deserialize(serialized_blk, feat_blk_serialize_len(idx_blk));
  TEST_ASSERT_NOT_NULL(deser_blk);

  // validate
  TEST_ASSERT(idx_blk->type == deser_blk->type);
  TEST_ASSERT(((feat_indexaction_blk_t*)idx_blk->block)->tag_len ==
              ((feat_indexaction_blk_t*)deser_blk->block)->tag_len);
  TEST_ASSERT_EQUAL_MEMORY(((feat_indexaction_blk_t*)idx_blk->block)->tag,
                           ((feat_indexaction_blk_t*)deser_blk->block)->tag,
                           ((feat_indexaction_blk_t*)idx_blk->block)->tag_len);

  // clean up
  free_feat_blk(idx_blk);
  free_feat_blk(deser_blk);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_sender);
  RUN_TEST(test_issuer);
  RUN_TEST(test_dust_deposit_return);
  RUN_TEST(test_timelock_milestone_index);
  RUN_TEST(test_timelock_unix);
  RUN_TEST(test_expiration_milestone_index);
  RUN_TEST(test_expiration_unix);
  RUN_TEST(test_metadata);
  RUN_TEST(test_indexaction);

  return UNITY_END();
}
