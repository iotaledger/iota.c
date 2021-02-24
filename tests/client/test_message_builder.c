// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/message_builder.h"

void setUp(void) {}

void tearDown(void) {}

void test_msg_indexation() {
  char const* const exp_str =
      "{\"networkId\":null,\"parentMessageIds\":[\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"0000000000000000000000000000000000000000000000000000000000000000\"],\"payload\":{\"type\":2,\"index\":"
      "\"48454C4C4F\",\"data\":\"48454C4C4F\"},\"nonce\":null}";

  byte_t idx_data[5] = {0x48, 0x45, 0x4C, 0x4C, 0x4F};
  byte_t empty_parent[IOTA_MESSAGE_ID_BYTES] = {};
  indexation_t* idx = indexation_create("HELLO", idx_data, sizeof(idx_data));
  TEST_ASSERT_NOT_NULL(idx);
  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = 2;
  msg->payload = idx;
  core_message_add_parent(msg, empty_parent);
  core_message_add_parent(msg, empty_parent);
  core_message_add_parent(msg, empty_parent);
  TEST_ASSERT_EQUAL_INT(3, core_message_parent_len(msg));

  char* str = message_to_json(msg);
  // printf("%s\n", str);
  TEST_ASSERT_NOT_NULL(str);
  TEST_ASSERT_EQUAL_STRING(exp_str, str);
  free(str);

  core_message_free(msg);
}

void test_msg_tx() {
  char const* const exp_str =
      "{\"networkId\":null,\"parentMessageIds\":[\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"0000000000000000000000000000000000000000000000000000000000000000\"],\"payload\":{\"type\":0,\"essence\":{"
      "\"type\":0,\"inputs\":[{\"type\":0,\"transactionId\":"
      "\"2BFBF7463B008C0298103121874F64B59D2B6172154AA14205DB2CE0BA553B03\",\"transactionOutputIndex\":0},{\"type\":0,"
      "\"transactionId\":\"0000000000000000000000000000000000000000000000000000000000000000\","
      "\"transactionOutputIndex\":1}],\"outputs\":[{\"type\":0,\"address\":{\"type\":0,\"address\":"
      "\"AD32258255E7CF927A4833F457F220B7187CF975E82AEEE2E23FCAE5056AB5F4\"},\"amount\":1000},{\"type\":0,\"address\":{"
      "\"type\":0,\"address\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"amount\":9999}],"
      "\"payload\":null},\"unlockBlocks\":[{\"type\":0,\"signature\":{\"type\":0,\"publicKey\":"
      "\"0000000000000000000000000000000000000000000000000000000000000000\",\"signature\":"
      "\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000\"}},{\"type\":1,\"reference\":0}]},\"nonce\":null}";

  byte_t tx_id0[TRANSACTION_ID_BYTES] = {0x2b, 0xfb, 0xf7, 0x46, 0x3b, 0x00, 0x8c, 0x02, 0x98, 0x10, 0x31,
                                         0x21, 0x87, 0x4f, 0x64, 0xb5, 0x9d, 0x2b, 0x61, 0x72, 0x15, 0x4a,
                                         0xa1, 0x42, 0x05, 0xdb, 0x2c, 0xe0, 0xba, 0x55, 0x3b, 0x03};
  byte_t tx_id1[TRANSACTION_ID_BYTES] = {};
  byte_t addr0[ED25519_ADDRESS_BYTES] = {0xad, 0x32, 0x25, 0x82, 0x55, 0xe7, 0xcf, 0x92, 0x7a, 0x48, 0x33,
                                         0xf4, 0x57, 0xf2, 0x20, 0xb7, 0x18, 0x7c, 0xf9, 0x75, 0xe8, 0x2a,
                                         0xee, 0xe2, 0xe2, 0x3f, 0xca, 0xe5, 0x05, 0x6a, 0xb5, 0xf4};
  byte_t addr1[ED25519_ADDRESS_BYTES] = {};
  byte_t empty_parent[IOTA_MESSAGE_ID_BYTES] = {};

  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  core_message_add_parent(msg, empty_parent);
  core_message_add_parent(msg, empty_parent);
  TEST_ASSERT_EQUAL_INT(2, core_message_parent_len(msg));

  transaction_payload_t* tx = tx_payload_new();
  TEST_ASSERT_NOT_NULL(tx);

  TEST_ASSERT(tx_payload_add_input(tx, tx_id0, 0) == 0);
  TEST_ASSERT(tx_payload_add_input(tx, tx_id1, 1) == 0);
  TEST_ASSERT(tx_payload_add_output(tx, OUTPUT_SINGLE_OUTPUT, addr0, 1000) == 0);
  TEST_ASSERT(tx_payload_add_output(tx, OUTPUT_SINGLE_OUTPUT, addr1, 9999) == 0);

  ed25519_signature_t sig = {};
  TEST_ASSERT(tx_payload_add_sig_block(tx, &sig) == 0);
  TEST_ASSERT(tx_payload_add_ref_block(tx, 0) == 0);
  // tx_payload_print(tx);

  // put tx payload into message
  msg->payload_type = 0;
  msg->payload = tx;

  char* msg_str = message_to_json(msg);
  TEST_ASSERT_NOT_NULL(msg_str);
  // printf("%s\n", msg_str);
  TEST_ASSERT_EQUAL_STRING(exp_str, msg_str);

  free(msg_str);
  // free message and sub entities
  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_msg_indexation);
  RUN_TEST(test_msg_tx);

  return UNITY_END();
}