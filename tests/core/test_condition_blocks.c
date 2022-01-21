// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/models/outputs/unlock_conditions.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_condition_addr() {
  // should be NULL
  TEST_ASSERT_NULL(new_cond_blk_addr(NULL));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  unlock_cond_blk_t* b = new_cond_blk_addr(&addr);
  TEST_ASSERT_NOT_NULL(b);
  // should be address unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)b->block));

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(cond_blk_serialize(b, buf, 4) == 0);
  size_t serial_len = cond_blk_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == cond_blk_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(cond_blk_deserialize(buf, serial_len - 1));
  unlock_cond_blk_t* deser_blk = cond_blk_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_blk);
  // validate block data
  TEST_ASSERT(b->type == deser_blk->type);
  TEST_ASSERT_TRUE(address_equal((address_t*)b->block, (address_t*)deser_blk->block));

  // clean up
  free_cond_blk(deser_blk);
  free_cond_blk(b);
}

void test_condition_dust() {
  // should be NULL
  TEST_ASSERT_NULL(new_cond_blk_dust(NULL, 1000000));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  unlock_cond_blk_t* b = new_cond_blk_dust(&addr, 100000000);
  TEST_ASSERT_NOT_NULL(b);
  // should be dist deposit unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_DUST);
  TEST_ASSERT_TRUE(address_equal(&addr, ((unlock_cond_dust_t*)b->block)->addr));
  TEST_ASSERT(((unlock_cond_dust_t*)b->block)->amount == 100000000);

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(cond_blk_serialize(b, buf, 4) == 0);
  size_t serial_len = cond_blk_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == cond_blk_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(cond_blk_deserialize(buf, serial_len - 1));
  unlock_cond_blk_t* deser_blk = cond_blk_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_blk);
  // validate block data
  TEST_ASSERT(b->type == deser_blk->type);
  TEST_ASSERT_TRUE(address_equal(((unlock_cond_dust_t*)b->block)->addr, ((unlock_cond_dust_t*)deser_blk->block)->addr));
  TEST_ASSERT(((unlock_cond_dust_t*)b->block)->amount == ((unlock_cond_dust_t*)deser_blk->block)->amount);

  // clean up
  free_cond_blk(deser_blk);
  free_cond_blk(b);
}

void test_condition_timelock() {
  // should be NULL, Timelock condition is invalid if Milestone Index and Unix time are zero.
  TEST_ASSERT_NULL(new_cond_blk_timelock(0, 0));

  unlock_cond_blk_t* b = new_cond_blk_timelock(100, 123);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT(b->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->milestone == 100);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->time == 123);
  free_cond_blk(b);

  b = new_cond_blk_timelock(0, 123);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT(b->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->milestone == 0);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->time == 123);
  free_cond_blk(b);

  b = new_cond_blk_timelock(100, 0);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT(b->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->milestone == 100);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->time == 0);

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(cond_blk_serialize(b, buf, 4) == 0);
  size_t serial_len = cond_blk_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == cond_blk_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(cond_blk_deserialize(buf, serial_len - 1));
  unlock_cond_blk_t* deser_blk = cond_blk_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_blk);
  // validate block data
  TEST_ASSERT(b->type == deser_blk->type);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->milestone == ((unlock_cond_timelock_t*)deser_blk->block)->milestone);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->block)->time == ((unlock_cond_timelock_t*)deser_blk->block)->time);

  // clean up
  free_cond_blk(deser_blk);
  free_cond_blk(b);
}

void test_condition_expiration() {
  // should be NULL
  TEST_ASSERT_NULL(new_cond_blk_expir(NULL, 0, 100));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);
  // should be NULL
  TEST_ASSERT_NULL(new_cond_blk_expir(&addr, 0, 0));

  unlock_cond_blk_t* b = new_cond_blk_expir(&addr, 0, 1023);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT(b->type == UNLOCK_COND_EXPIRATION);
  TEST_ASSERT_TRUE(address_equal(&addr, ((unlock_cond_expir_t*)b->block)->addr));
  TEST_ASSERT(((unlock_cond_expir_t*)b->block)->milestone == 0);
  TEST_ASSERT(((unlock_cond_expir_t*)b->block)->time == 1023);
  free_cond_blk(b);

  b = new_cond_blk_expir(&addr, 100, 0);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT(b->type == UNLOCK_COND_EXPIRATION);
  TEST_ASSERT_TRUE(address_equal(&addr, ((unlock_cond_expir_t*)b->block)->addr));
  TEST_ASSERT(((unlock_cond_expir_t*)b->block)->milestone == 100);
  TEST_ASSERT(((unlock_cond_expir_t*)b->block)->time == 0);

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(cond_blk_serialize(b, buf, 4) == 0);
  size_t serial_len = cond_blk_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == cond_blk_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(cond_blk_deserialize(buf, serial_len - 1));
  unlock_cond_blk_t* deser_blk = cond_blk_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_blk);
  // validate block data
  TEST_ASSERT(b->type == deser_blk->type);
  TEST_ASSERT_TRUE(
      address_equal(((unlock_cond_expir_t*)b->block)->addr, ((unlock_cond_expir_t*)deser_blk->block)->addr));
  TEST_ASSERT(((unlock_cond_expir_t*)b->block)->milestone == ((unlock_cond_expir_t*)deser_blk->block)->milestone);
  TEST_ASSERT(((unlock_cond_expir_t*)b->block)->time == ((unlock_cond_expir_t*)deser_blk->block)->time);

  // clean up
  free_cond_blk(deser_blk);
  free_cond_blk(b);
}

void test_condition_state() {
  // should be NULL
  TEST_ASSERT_NULL(new_cond_blk_state(NULL));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  unlock_cond_blk_t* b = new_cond_blk_state(&addr);
  TEST_ASSERT_NOT_NULL(b);
  // should be address unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_STATE);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)b->block));

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(cond_blk_serialize(b, buf, 4) == 0);
  size_t serial_len = cond_blk_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == cond_blk_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(cond_blk_deserialize(buf, serial_len - 1));
  unlock_cond_blk_t* deser_blk = cond_blk_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_blk);
  // validate block data
  TEST_ASSERT(b->type == deser_blk->type);
  TEST_ASSERT_TRUE(address_equal((address_t*)b->block, (address_t*)deser_blk->block));

  // clean up
  free_cond_blk(deser_blk);
  free_cond_blk(b);
}

void test_condition_governor() {
  // should be NULL
  TEST_ASSERT_NULL(new_cond_blk_governor(NULL));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  unlock_cond_blk_t* b = new_cond_blk_governor(&addr);
  TEST_ASSERT_NOT_NULL(b);
  // should be address unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_GOVERNOR);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)b->block));

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(cond_blk_serialize(b, buf, 4) == 0);
  size_t serial_len = cond_blk_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == cond_blk_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(cond_blk_deserialize(buf, serial_len - 1));
  unlock_cond_blk_t* deser_blk = cond_blk_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_blk);
  // validate block data
  TEST_ASSERT(b->type == deser_blk->type);
  TEST_ASSERT_TRUE(address_equal((address_t*)b->block, (address_t*)deser_blk->block));

  // clean up
  free_cond_blk(deser_blk);
  free_cond_blk(b);
}

void test_condition_list() {}

int main() {
  UNITY_BEGIN();

  // Condition blocks
  RUN_TEST(test_condition_addr);
  RUN_TEST(test_condition_dust);
  RUN_TEST(test_condition_timelock);
  RUN_TEST(test_condition_expiration);
  RUN_TEST(test_condition_state);
  RUN_TEST(test_condition_governor);

  // Condition block list
  RUN_TEST(test_condition_list);

  return UNITY_END();
}
