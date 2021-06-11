// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <unity/unity.h>

#include "core/models/message.h"

void setUp(void) {}

void tearDown(void) {}

void test_message_with_tx() {
  byte_t tx_id0[TRANSACTION_ID_BYTES] = {};
  byte_t addr0[ED25519_ADDRESS_BYTES] = {0x51, 0x55, 0x82, 0xfe, 0x64, 0x8b, 0x0f, 0x10, 0xa2, 0xb2, 0xa1,
                                         0xb9, 0x1d, 0x75, 0x02, 0x19, 0x0c, 0x97, 0x9b, 0xaa, 0xbf, 0xee,
                                         0x85, 0xb6, 0xbb, 0xb5, 0x02, 0x06, 0x92, 0xe5, 0x5d, 0x16};
  byte_t addr1[ED25519_ADDRESS_BYTES] = {0x69, 0x20, 0xb1, 0x76, 0xf6, 0x13, 0xec, 0x7b, 0xe5, 0x9e, 0x68,
                                         0xfc, 0x68, 0xf5, 0x97, 0xeb, 0x33, 0x93, 0xaf, 0x80, 0xf7, 0x4c,
                                         0x7c, 0x3d, 0xb7, 0x81, 0x98, 0x14, 0x7d, 0x5f, 0x1f, 0x92};

  iota_keypair_t seed_keypair = {};
  TEST_ASSERT(hex_2_bin("f7868ab6bb55800b77b8b74191ad8285a9bf428ace579d541fda47661803ff44", 64, seed_keypair.pub,
                        ED_PUBLIC_KEY_BYTES) == 0);
  TEST_ASSERT(
      hex_2_bin("256a818b2aac458941f7274985a410e57fb750f3a3a67969ece5bd9ae7eef5b2f7868ab6bb55800b77b8b74191ad8285"
                "a9bf428ace579d541fda47661803ff44",
                128, seed_keypair.priv, ED_PRIVATE_KEY_BYTES) == 0);

  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);

  transaction_payload_t* tx = tx_payload_new();
  TEST_ASSERT_NOT_NULL(tx);

  TEST_ASSERT(tx_payload_add_input_with_key(tx, tx_id0, 0, seed_keypair.pub, seed_keypair.priv) == 0);
  TEST_ASSERT(tx_payload_add_output(tx, OUTPUT_SINGLE_OUTPUT, addr0, 1000) == 0);
  TEST_ASSERT(tx_payload_add_output(tx, OUTPUT_SINGLE_OUTPUT, addr1, 2779530283276761) == 0);

  // put tx payload into message
  msg->payload_type = 0;
  msg->payload = tx;

  TEST_ASSERT(core_message_sign_transaction(msg) == 0);

  // tx_payload_print(tx);

  // free message and sub entities
  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_message_with_tx);

  return UNITY_END();
}
