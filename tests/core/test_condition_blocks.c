// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/constants.h"
#include "core/models/outputs/unlock_conditions.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_condition_addr() {
  // should be NULL
  TEST_ASSERT_NULL(condition_addr_new(NULL));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  unlock_cond_t* b = condition_addr_new(&addr);
  TEST_ASSERT_NOT_NULL(b);
  // should be address unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)b->obj));

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(condition_serialize(b, buf, 4) == 0);
  size_t serial_len = condition_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == condition_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(condition_deserialize(buf, serial_len - 1));
  unlock_cond_t* deser_cond = condition_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_cond);
  // validate unlock condition data
  TEST_ASSERT(b->type == deser_cond->type);
  TEST_ASSERT_TRUE(address_equal((address_t*)b->obj, (address_t*)deser_cond->obj));

  // clean up
  condition_free(deser_cond);
  condition_free(b);
}

void test_condition_storage() {
  // should be NULL
  TEST_ASSERT_NULL(condition_storage_new(NULL, 1000000));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  unlock_cond_t* b = condition_storage_new(&addr, 100000000);
  TEST_ASSERT_NOT_NULL(b);
  // should be dist deposit unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_STORAGE);
  TEST_ASSERT_TRUE(address_equal(&addr, ((unlock_cond_storage_t*)b->obj)->addr));
  TEST_ASSERT(((unlock_cond_storage_t*)b->obj)->amount == 100000000);

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(condition_serialize(b, buf, 4) == 0);
  size_t serial_len = condition_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == condition_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(condition_deserialize(buf, serial_len - 1));
  unlock_cond_t* deser_cond = condition_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_cond);
  // validate unlock condition data
  TEST_ASSERT(b->type == deser_cond->type);
  TEST_ASSERT_TRUE(
      address_equal(((unlock_cond_storage_t*)b->obj)->addr, ((unlock_cond_storage_t*)deser_cond->obj)->addr));
  TEST_ASSERT(((unlock_cond_storage_t*)b->obj)->amount == ((unlock_cond_storage_t*)deser_cond->obj)->amount);

  // clean up
  condition_free(deser_cond);
  condition_free(b);
}

void test_condition_timelock() {
  // should be NULL, Timelock condition is invalid if Milestone Index and Unix time are zero.
  TEST_ASSERT_NULL(condition_timelock_new(0));

  unlock_cond_t* b = condition_timelock_new(123);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT(b->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->obj)->time == 123);

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(condition_serialize(b, buf, 1) == 0);
  size_t serial_len = condition_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == condition_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(condition_deserialize(buf, serial_len - 1));
  unlock_cond_t* deser_cond = condition_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_cond);
  // validate unlock condition data
  TEST_ASSERT(b->type == deser_cond->type);
  TEST_ASSERT(((unlock_cond_timelock_t*)b->obj)->time == ((unlock_cond_timelock_t*)deser_cond->obj)->time);

  // clean up
  condition_free(deser_cond);
  condition_free(b);
}

void test_condition_expiration() {
  // should be NULL
  TEST_ASSERT_NULL(condition_expir_new(NULL, 0));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);
  // should be NULL
  TEST_ASSERT_NULL(condition_expir_new(&addr, 0));

  unlock_cond_t* b = condition_expir_new(&addr, 1023);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT(b->type == UNLOCK_COND_EXPIRATION);
  TEST_ASSERT_TRUE(address_equal(&addr, ((unlock_cond_expir_t*)b->obj)->addr));
  TEST_ASSERT(((unlock_cond_expir_t*)b->obj)->time == 1023);

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(condition_serialize(b, buf, 4) == 0);
  size_t serial_len = condition_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == condition_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(condition_deserialize(buf, serial_len - 1));
  unlock_cond_t* deser_cond = condition_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_cond);
  // validate unlock condition data
  TEST_ASSERT(b->type == deser_cond->type);
  TEST_ASSERT_TRUE(address_equal(((unlock_cond_expir_t*)b->obj)->addr, ((unlock_cond_expir_t*)deser_cond->obj)->addr));
  TEST_ASSERT(((unlock_cond_expir_t*)b->obj)->time == ((unlock_cond_expir_t*)deser_cond->obj)->time);

  // clean up
  condition_free(deser_cond);
  condition_free(b);
}

void test_condition_state() {
  // should be NULL
  TEST_ASSERT_NULL(condition_state_new(NULL));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  unlock_cond_t* b = condition_state_new(&addr);
  TEST_ASSERT_NOT_NULL(b);
  // should be address unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_STATE);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)b->obj));

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(condition_serialize(b, buf, 4) == 0);
  size_t serial_len = condition_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == condition_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(condition_deserialize(buf, serial_len - 1));
  unlock_cond_t* deser_cond = condition_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_cond);
  // validate unlock condition data
  TEST_ASSERT(b->type == deser_cond->type);
  TEST_ASSERT_TRUE(address_equal((address_t*)b->obj, (address_t*)deser_cond->obj));

  // clean up
  condition_free(deser_cond);
  condition_free(b);
}

void test_condition_governor() {
  // should be NULL
  TEST_ASSERT_NULL(condition_governor_new(NULL));

  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  unlock_cond_t* b = condition_governor_new(&addr);
  TEST_ASSERT_NOT_NULL(b);
  // should be address unlock condition
  TEST_ASSERT(b->type == UNLOCK_COND_GOVERNOR);
  TEST_ASSERT_TRUE(address_equal(&addr, (address_t*)b->obj));

  // serialization tests
  byte_t buf[64] = {};
  // insufficient buffer
  TEST_ASSERT(condition_serialize(b, buf, 4) == 0);
  size_t serial_len = condition_serialize(b, buf, sizeof(buf));
  // should be equal to expected length
  TEST_ASSERT(serial_len == condition_serialize_len(b));
  // incorrect buffer length
  TEST_ASSERT_NULL(condition_deserialize(buf, serial_len - 1));
  unlock_cond_t* deser_cond = condition_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_cond);
  // validate unlock condition data
  TEST_ASSERT(b->type == deser_cond->type);
  TEST_ASSERT_TRUE(address_equal((address_t*)b->obj, (address_t*)deser_cond->obj));

  // clean up
  condition_free(deser_cond);
  condition_free(b);
}

void test_condition_list() {
  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  // empty list
  unlock_cond_list_t* list = condition_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(condition_list_len(list) == 0);

  unlock_cond_t* cond = NULL;
  // 0: add timelock
  cond = condition_timelock_new(100);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  TEST_ASSERT(condition_list_len(list) == 1);
  // add one more timelock, should be failed
  TEST_ASSERT(condition_list_add(&list, cond) != 0);
  TEST_ASSERT(condition_list_len(list) == 1);

  // 1: add state controller
  condition_free(cond);
  cond = condition_state_new(&addr);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  TEST_ASSERT(condition_list_len(list) == 2);
  // add one more state controller, should be failed
  TEST_ASSERT(condition_list_add(&list, cond) != 0);
  TEST_ASSERT(condition_list_len(list) == 2);

  // 2: add Address unlock condition
  condition_free(cond);
  cond = condition_addr_new(&addr);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  TEST_ASSERT(condition_list_len(list) == 3);
  // add one more address, should be failed
  TEST_ASSERT(condition_list_add(&list, cond) != 0);
  TEST_ASSERT(condition_list_len(list) == 3);

  // 3: add Governor unlock condition
  condition_free(cond);
  cond = condition_governor_new(&addr);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  TEST_ASSERT(condition_list_len(list) == 4);
  // add one more address, should be failed
  TEST_ASSERT(condition_list_add(&list, cond) != 0);
  TEST_ASSERT(condition_list_len(list) == 4);

  // 4: add Storage Deposit
  condition_free(cond);
  cond = condition_storage_new(&addr, 1000000);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  TEST_ASSERT(condition_list_len(list) == 5);
  // add one more address, should be failed
  TEST_ASSERT(condition_list_add(&list, cond) != 0);
  TEST_ASSERT(condition_list_len(list) == 5);

  // 5: add Expiration unlock condition
  condition_free(cond);
  cond = condition_expir_new(&addr, 1234546);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  TEST_ASSERT(condition_list_len(list) == 6);
  // add one more address, should be failed
  TEST_ASSERT(condition_list_add(&list, cond) != 0);
  TEST_ASSERT(condition_list_len(list) == 6);
  // no needed
  condition_free(cond);

  condition_list_print(list, 0);
  // check the adding order
  TEST_ASSERT(condition_list_get(list, 0)->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(condition_list_get(list, 1)->type == UNLOCK_COND_STATE);
  TEST_ASSERT(condition_list_get(list, 2)->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT(condition_list_get(list, 3)->type == UNLOCK_COND_GOVERNOR);
  TEST_ASSERT(condition_list_get(list, 4)->type == UNLOCK_COND_STORAGE);
  TEST_ASSERT(condition_list_get(list, 5)->type == UNLOCK_COND_EXPIRATION);

  unlock_cond_list_t* list2 = condition_list_clone(list);
  TEST_ASSERT_NOT_NULL(list2);
  for (uint8_t i = 0; i < condition_list_len(list); i++) {
    TEST_ASSERT(condition_list_get(list, i)->type == condition_list_get(list2, i)->type);
  }

  // test sort function
  condition_list_sort(&list);
  // should be in order
  TEST_ASSERT(condition_list_get(list, 0)->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT(condition_list_get(list, 1)->type == UNLOCK_COND_STORAGE);
  TEST_ASSERT(condition_list_get(list, 2)->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(condition_list_get(list, 3)->type == UNLOCK_COND_EXPIRATION);
  TEST_ASSERT(condition_list_get(list, 4)->type == UNLOCK_COND_STATE);
  TEST_ASSERT(condition_list_get(list, 5)->type == UNLOCK_COND_GOVERNOR);

  // clean up
  condition_list_free(list);
  condition_list_free(list2);
}

void test_condition_list_syntactic() {
  // random ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  // empty list
  unlock_cond_list_t* list = condition_list_new();
  TEST_ASSERT_NULL(list);
  TEST_ASSERT(condition_list_len(list) == 0);
  TEST_ASSERT(condition_list_syntactic(&list) != 0);

  unlock_cond_t* cond = NULL;
  // 0: add timelock
  cond = condition_timelock_new(100);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  // 1: add state controller
  condition_free(cond);
  cond = condition_state_new(&addr);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  // 2: add Address unlock condition
  condition_free(cond);
  cond = condition_addr_new(&addr);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);
  // 3: add Governor unlock condition
  condition_free(cond);
  cond = condition_governor_new(&addr);
  TEST_ASSERT(condition_list_add(&list, cond) == 0);

  // syntactic check
  TEST_ASSERT(condition_list_syntactic(&list) == 0);

  // serialization
  byte_t buf[128] = {};
  size_t serial_len = condition_list_serialize_len(list);
  TEST_ASSERT(serial_len > 0);
  // insufficient buffer length
  TEST_ASSERT(condition_list_serialize(&list, buf, serial_len - 1) == 0);

  TEST_ASSERT(condition_list_serialize(&list, buf, sizeof(buf)) == serial_len);
  TEST_ASSERT_NULL(condition_list_deserialize(buf, serial_len - 1));

  unlock_cond_list_t* deser_list = condition_list_deserialize(buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(deser_list);

  TEST_ASSERT(condition_list_get(deser_list, 0)->type == UNLOCK_COND_ADDRESS);
  TEST_ASSERT(condition_list_get(deser_list, 1)->type == UNLOCK_COND_TIMELOCK);
  TEST_ASSERT(condition_list_get(deser_list, 2)->type == UNLOCK_COND_STATE);
  TEST_ASSERT(condition_list_get(deser_list, 3)->type == UNLOCK_COND_GOVERNOR);

  // no needed
  condition_free(cond);
  condition_list_free(list);
  condition_list_free(deser_list);
}

int main() {
  UNITY_BEGIN();

  // Unlock Conditions
  RUN_TEST(test_condition_addr);
  RUN_TEST(test_condition_storage);
  RUN_TEST(test_condition_timelock);
  RUN_TEST(test_condition_expiration);
  RUN_TEST(test_condition_state);
  RUN_TEST(test_condition_governor);

  // Unlock Condition list
  // testing list opreations only
  RUN_TEST(test_condition_list);
  // testing serialization and synatctic
  RUN_TEST(test_condition_list_syntactic);

  return UNITY_END();
}
