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

void test_condition_list() {
  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  // empty list
  cond_blk_list_t* list = new_cond_blk_list();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(cond_blk_list_len(list) == 0);

  unlock_cond_blk_t* blk = NULL;
  // 0: add timelock
  blk = new_cond_blk_timelock(100, 0);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  TEST_ASSERT(cond_blk_list_len(list) == 1);
  // add one more timelock, should be failed
  TEST_ASSERT(cond_blk_list_add(&list, blk) != 0);
  TEST_ASSERT(cond_blk_list_len(list) == 1);

  // 1: add state controller
  free_cond_blk(blk);
  blk = new_cond_blk_state(&addr);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  TEST_ASSERT(cond_blk_list_len(list) == 2);
  // add one more state controller, should be failed
  TEST_ASSERT(cond_blk_list_add(&list, blk) != 0);
  TEST_ASSERT(cond_blk_list_len(list) == 2);

  // 2: add Address unlock condition
  free_cond_blk(blk);
  blk = new_cond_blk_addr(&addr);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  TEST_ASSERT(cond_blk_list_len(list) == 3);
  // add one more address, should be failed
  TEST_ASSERT(cond_blk_list_add(&list, blk) != 0);
  TEST_ASSERT(cond_blk_list_len(list) == 3);

  // 3: add Governor unlock condition
  free_cond_blk(blk);
  blk = new_cond_blk_governor(&addr);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  TEST_ASSERT(cond_blk_list_len(list) == 4);
  // add one more address, should be failed
  TEST_ASSERT(cond_blk_list_add(&list, blk) != 0);
  TEST_ASSERT(cond_blk_list_len(list) == 4);

  // 4: add Dust Deposit
  free_cond_blk(blk);
  blk = new_cond_blk_dust(&addr, 1000000);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  TEST_ASSERT(cond_blk_list_len(list) == 5);
  // add one more address, should be failed
  TEST_ASSERT(cond_blk_list_add(&list, blk) != 0);
  TEST_ASSERT(cond_blk_list_len(list) == 5);

  // 5: add Expiration unlock condition
  free_cond_blk(blk);
  blk = new_cond_blk_expir(&addr, 321, 1234546);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  TEST_ASSERT(cond_blk_list_len(list) == 6);
  // add one more address, should be failed
  TEST_ASSERT(cond_blk_list_add(&list, blk) != 0);
  TEST_ASSERT(cond_blk_list_len(list) == 6);
  // no needed
  free_cond_blk(blk);

  cond_blk_list_print(list, 0);
  // check the adding order
  TEST_ASSERT(cond_blk_list_get(list, 0)->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(cond_blk_list_get(list, 1)->type == UNLOCK_COND_STATE);
  TEST_ASSERT(cond_blk_list_get(list, 2)->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT(cond_blk_list_get(list, 3)->type == UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(cond_blk_list_get(list, 4)->type == UNLOCK_COND_DUST);
  TEST_ASSERT(cond_blk_list_get(list, 5)->type == UNLOCK_COND_EXPIRATION);

  cond_blk_list_t* list2 = cond_blk_list_clone(list);
  TEST_ASSERT_NOT_NULL(list2);
  for (uint8_t i = 0; i < cond_blk_list_len(list); i++) {
    TEST_ASSERT(cond_blk_list_get(list, i)->type == cond_blk_list_get(list2, i)->type);
  }

  // test sort function
  cond_blk_list_sort(&list);
  // should be in order
  TEST_ASSERT(cond_blk_list_get(list, 0)->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT(cond_blk_list_get(list, 1)->type == UNLOCK_COND_DUST);
  TEST_ASSERT(cond_blk_list_get(list, 2)->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(cond_blk_list_get(list, 3)->type == UNLOCK_COND_EXPIRATION);
  TEST_ASSERT(cond_blk_list_get(list, 4)->type == UNLOCK_COND_STATE);
  TEST_ASSERT(cond_blk_list_get(list, 5)->type == UNLOCK_COND_GOVERNOR);

  // clean up
  free_cond_blk_list(list);
  free_cond_blk_list(list2);
}

void test_condition_list_syntactic() {
  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  // empty list
  cond_blk_list_t* list = new_cond_blk_list();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(cond_blk_list_len(list) == 0);
  TEST_ASSERT(cond_blk_list_syntactic(&list) != 0);

  unlock_cond_blk_t* blk = NULL;
  // 0: add timelock
  blk = new_cond_blk_timelock(100, 0);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  // 1: add state controller
  free_cond_blk(blk);
  blk = new_cond_blk_state(&addr);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  // 2: add Address unlock condition
  free_cond_blk(blk);
  blk = new_cond_blk_addr(&addr);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);
  // 3: add Governor unlock condition
  free_cond_blk(blk);
  blk = new_cond_blk_governor(&addr);
  TEST_ASSERT(cond_blk_list_add(&list, blk) == 0);

  // syntactic check
  TEST_ASSERT(cond_blk_list_syntactic(&list) == 0);

  // serialization
  byte_t buf[128] = {};
  size_t serial_len = cond_blk_list_serialize_len(list);
  TEST_ASSERT(serial_len > 0);
  // insufficient buffer length
  TEST_ASSERT(cond_blk_list_serialize(&list, buf, serial_len - 1) == 0);

  TEST_ASSERT(cond_blk_list_serialize(&list, buf, sizeof(buf)) == serial_len);
  TEST_ASSERT_NULL(cond_blk_list_deserialize(buf, serial_len - 1));

  cond_blk_list_t* deser_list = cond_blk_list_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_list);

  TEST_ASSERT(cond_blk_list_get(deser_list, 0)->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT(cond_blk_list_get(deser_list, 1)->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(cond_blk_list_get(deser_list, 2)->type == UNLOCK_COND_STATE);
  TEST_ASSERT(cond_blk_list_get(deser_list, 3)->type == UNLOCK_COND_GOVERNOR);

  // no needed
  free_cond_blk(blk);
  free_cond_blk_list(list);
  free_cond_blk_list(deser_list);
}

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
  // testing list opreations only
  RUN_TEST(test_condition_list);
  // testing serialization and synatctic
  RUN_TEST(test_condition_list_syntactic);

  return UNITY_END();
}
