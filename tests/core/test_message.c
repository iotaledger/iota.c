// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "core/models/message.h"
#include "core/models/outputs/output_extended.h"
#include "core/models/outputs/outputs.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

static output_extended_t* create_output_extended_one() {
  // create ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942", ADDRESS_ED25519_HEX_BYTES,
                        addr.address, ADDRESS_ED25519_BYTES) == 0);

  // create address unlock condition
  unlock_cond_blk_t* addr_unlock_cond = cond_blk_addr_new(&addr);
  TEST_ASSERT_NOT_NULL(addr_unlock_cond);

  // crete unlock conditions list
  cond_blk_list_t* unlock_conditions = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conditions, addr_unlock_cond) == 0);

  // create Extended Output
  output_extended_t* output = output_extended_new(10000000, NULL, unlock_conditions, NULL);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  cond_blk_free(addr_unlock_cond);
  cond_blk_list_free(unlock_conditions);

  return output;
}

static output_extended_t* create_output_extended_two() {
  // create ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("60200bad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe", ADDRESS_ED25519_HEX_BYTES,
                        addr.address, ADDRESS_ED25519_BYTES) == 0);

  // create address unlock condition
  unlock_cond_blk_t* addr_unlock_cond = cond_blk_addr_new(&addr);
  TEST_ASSERT_NOT_NULL(addr_unlock_cond);

  // crete unlock conditions list
  cond_blk_list_t* unlock_conditions = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conditions, addr_unlock_cond) == 0);

  // create Extended Output
  output_extended_t* output = output_extended_new(2779530273277761, NULL, unlock_conditions, NULL);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  cond_blk_free(addr_unlock_cond);
  cond_blk_list_free(unlock_conditions);

  return output;
}

static byte_t* create_signature_unlock_block() {
  byte_t pub_key[ED_PUBLIC_KEY_BYTES] = {};
  TEST_ASSERT(hex_2_bin("31f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb",
                        BIN_TO_HEX_BYTES(ED_PUBLIC_KEY_BYTES), pub_key, sizeof(pub_key)) == 0);
  byte_t sig[ED_SIGNATURE_BYTES] = {};
  TEST_ASSERT(hex_2_bin("1b51aab768dd145de99fc3710c7b05963803f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e1"
                        "60efc9fe034f810ad0cc4b0210adaafd0a",
                        BIN_TO_HEX_BYTES(ED_SIGNATURE_BYTES), sig, sizeof(sig)) == 0);

  // create a signature unlock block
  byte_t* signature = malloc(ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_NOT_NULL(signature);

  signature[0] = 0;  // denotes ed25519 signature
  memcpy(signature + 1, pub_key, ED_PUBLIC_KEY_BYTES);
  memcpy(signature + (1 + ED_PUBLIC_KEY_BYTES), sig, ED_SIGNATURE_BYTES);

  return signature;
}

void test_message_with_tx() {
#if 0
  byte_t tx_id0[TRANSACTION_ID_BYTES] = {};
  byte_t addr0[ADDRESS_ED25519_BYTES] = {0x51, 0x55, 0x82, 0xfe, 0x64, 0x8b, 0x0f, 0x10, 0xa2, 0xb2, 0xa1,
                                         0xb9, 0x1d, 0x75, 0x02, 0x19, 0x0c, 0x97, 0x9b, 0xaa, 0xbf, 0xee,
                                         0x85, 0xb6, 0xbb, 0xb5, 0x02, 0x06, 0x92, 0xe5, 0x5d, 0x16};
  byte_t addr1[ADDRESS_ED25519_BYTES] = {0x69, 0x20, 0xb1, 0x76, 0xf6, 0x13, 0xec, 0x7b, 0xe5, 0x9e, 0x68,
                                         0xfc, 0x68, 0xf5, 0x97, 0xeb, 0x33, 0x93, 0xaf, 0x80, 0xf7, 0x4c,
                                         0x7c, 0x3d, 0xb7, 0x81, 0x98, 0x14, 0x7d, 0x5f, 0x1f, 0x92};

  ed25519_keypair_t seed_keypair = {};
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

  tx_payload_print(tx);

  // free message and sub entities
  core_message_free(msg);
#endif
}

void test_message_with_tx_serialize() {
  char test_serialized_data_str[] =
      "0a6bb59d7ae450750432cb4c7602013ba16231fd9bf1bdd9c1b9a403c07dd155ff9979a72684dafdb364463ce32fb6ef011cfff38b736b46"
      "6f974a92429767650777cd9b77cf7f26bfe1a518eccfa39a03aeb4b425a51db030eeec1c32654c1c943bc008eb4dc8d862ef8728a24dc086"
      "4a94b4f629d8ed7f56003cf84483700bac919d02622f20dc7007010000000000000001000000000000000000000000000000000000000000"
      "00000000000000000000000000000002000380969800000000000001000021e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c"
      "947b1d79c942000341c794d2f7df09000001000060200bad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe00170000"
      "00050000000e484f524e45542046415543455400000000000100000031f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc1"
      "62a095cb1b51aab768dd145de99fc3710c7b05963803f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe03"
      "4f810ad0cc4b0210adaafd0a15af000000000000";

  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);

  // add protocol version
  msg->protocol_version = 2;

  // add message parents
  byte_t parent_id_1[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("32cb4c7602013ba16231fd9bf1bdd9c1b9a403c07dd155ff9979a72684dafdb3", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_1, sizeof(parent_id_1));
  byte_t parent_id_2[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("64463ce32fb6ef011cfff38b736b466f974a92429767650777cd9b77cf7f26bf", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_2, sizeof(parent_id_2));
  byte_t parent_id_3[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("e1a518eccfa39a03aeb4b425a51db030eeec1c32654c1c943bc008eb4dc8d862", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_3, sizeof(parent_id_3));
  byte_t parent_id_4[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("ef8728a24dc0864a94b4f629d8ed7f56003cf84483700bac919d02622f20dc70", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_4, sizeof(parent_id_4));
  core_message_add_parent(msg, parent_id_1);
  core_message_add_parent(msg, parent_id_2);
  core_message_add_parent(msg, parent_id_3);
  core_message_add_parent(msg, parent_id_4);
  TEST_ASSERT_EQUAL_UINT8(4, core_message_parent_len(msg));

  // add message payload
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;
  msg->payload = tx_payload_new();

  // add message nonce
  msg->nonce = 44821;

  // add transaction essence
  transaction_essence_t* essence = ((transaction_payload_t*)msg->payload)->essence;
  TEST_ASSERT_NOT_NULL(essence);

  // add input with id0
  byte_t input_id0[IOTA_TRANSACTION_ID_BYTES];
  hex_2_bin("0000000000000000000000000000000000000000000000000000000000000000",
            BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES), input_id0, sizeof(input_id0));
  TEST_ASSERT(tx_essence_add_input(essence, 0, input_id0, 0, NULL) == 0);

  // add extended output one
  output_extended_t* extended_output_one = create_output_extended_one();
  TEST_ASSERT(tx_essence_add_output(essence, OUTPUT_EXTENDED, extended_output_one) == 0);

  // add extended output two
  output_extended_t* extended_output_two = create_output_extended_two();
  TEST_ASSERT(tx_essence_add_output(essence, OUTPUT_EXTENDED, extended_output_two) == 0);

  // add tagged data payload
  char const* const hornet_faucet = "HORNET FAUCET";
  tagged_data_t* tagged_data = tagged_data_create((byte_t*)hornet_faucet, strlen(hornet_faucet) + 1, NULL, 0);
  TEST_ASSERT_NOT_NULL(tagged_data);
  TEST_ASSERT(tx_essence_add_payload(essence, CORE_MESSAGE_PAYLOAD_TAGGED, tagged_data) == 0);

  // add signature unlock block
  byte_t* signature = create_signature_unlock_block();
  TEST_ASSERT(unlock_blocks_add_signature(&((transaction_payload_t*)msg->payload)->unlock_blocks, signature,
                                          ED25519_SIGNATURE_BLOCK_BYTES) == 0);

  // serialize core message
  size_t core_message_expected_len = core_message_serialize_len(msg);
  TEST_ASSERT(core_message_expected_len != 0);
  byte_t* core_message_buf = malloc(core_message_expected_len);
  TEST_ASSERT_NOT_NULL(core_message_buf);
  TEST_ASSERT(core_message_serialize(msg, core_message_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(core_message_serialize(msg, core_message_buf, core_message_expected_len) == core_message_expected_len);

  // validate core message
  size_t serialized_data_hex_str_len = BIN_TO_HEX_STR_BYTES(core_message_expected_len);
  TEST_ASSERT_EQUAL_INT(sizeof(test_serialized_data_str), serialized_data_hex_str_len);
  char* serialized_data_hex_str = malloc(serialized_data_hex_str_len);
  TEST_ASSERT_NOT_NULL(serialized_data_hex_str);
  bin_2_hex(core_message_buf, core_message_expected_len, serialized_data_hex_str, serialized_data_hex_str_len);
  TEST_ASSERT_EQUAL_MEMORY(test_serialized_data_str, serialized_data_hex_str, serialized_data_hex_str_len);

  // print serialized core message
  printf("Serialized messages: ");
  dump_hex_str(core_message_buf, core_message_expected_len);

  // print core message
  core_message_print(msg, 0);

  // clean up
  free(serialized_data_hex_str);
  free(signature);
  free(core_message_buf);
  output_extended_free(extended_output_one);
  output_extended_free(extended_output_two);
  core_message_free(msg);
}

void test_message_with_tagged_data_serialize() {
  char test_serialized_data_str[] =
      "0a6bb59d7ae4507504177fc9af60009e4e4e835baf7fe9f5f05aaf9b4e391e605d67cb722bf556266960f767d157c2cfb12533082abb3085"
      "a22665ef19f7bf77a3e39a2b223f33108a6af00016d7fbe8e5aa55c6688db5d5eb4241a562c4bd89ce8e6c0bc3fc3f6458fe53e33c0b9569"
      "9172a9537f116ee6a61c2cc153e4f857071bde2f72e23132881f000000050000000b696f74612e63206c6962000b00000048656c6c6f2057"
      "6f726c6460e6000000000000";

  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);

  // add protocol version
  msg->protocol_version = 2;

  // add message parents
  byte_t parent_id_1[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("177fc9af60009e4e4e835baf7fe9f5f05aaf9b4e391e605d67cb722bf5562669", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_1, sizeof(parent_id_1));
  byte_t parent_id_2[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("60f767d157c2cfb12533082abb3085a22665ef19f7bf77a3e39a2b223f33108a", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_2, sizeof(parent_id_2));
  byte_t parent_id_3[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("6af00016d7fbe8e5aa55c6688db5d5eb4241a562c4bd89ce8e6c0bc3fc3f6458", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_3, sizeof(parent_id_3));
  byte_t parent_id_4[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("fe53e33c0b95699172a9537f116ee6a61c2cc153e4f857071bde2f72e2313288", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            parent_id_4, sizeof(parent_id_4));
  core_message_add_parent(msg, parent_id_1);
  core_message_add_parent(msg, parent_id_2);
  core_message_add_parent(msg, parent_id_3);
  core_message_add_parent(msg, parent_id_4);
  TEST_ASSERT_EQUAL_UINT8(4, core_message_parent_len(msg));

  // add message payload
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TAGGED;

  // create tagged data
  byte_t data[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64};
  char const* const iotac_lib = "iota.c lib";
  msg->payload = tagged_data_create((byte_t*)iotac_lib, strlen(iotac_lib) + 1, data, sizeof(data));

  // add message nonce
  msg->nonce = 58976;

  // serialize core message
  size_t core_message_expected_len = core_message_serialize_len(msg);
  TEST_ASSERT(core_message_expected_len != 0);
  byte_t* core_message_buf = malloc(core_message_expected_len);
  TEST_ASSERT_NOT_NULL(core_message_buf);
  TEST_ASSERT(core_message_serialize(msg, core_message_buf, 1) == 0);  // expect serialization fails
  TEST_ASSERT(core_message_serialize(msg, core_message_buf, core_message_expected_len) == core_message_expected_len);

  // validate core message
  size_t serialized_data_hex_str_len = BIN_TO_HEX_STR_BYTES(core_message_expected_len);
  TEST_ASSERT_EQUAL_INT(sizeof(test_serialized_data_str), serialized_data_hex_str_len);
  char* serialized_data_hex_str = malloc(serialized_data_hex_str_len);
  TEST_ASSERT_NOT_NULL(serialized_data_hex_str);
  bin_2_hex(core_message_buf, core_message_expected_len, serialized_data_hex_str, serialized_data_hex_str_len);
  TEST_ASSERT_EQUAL_MEMORY(test_serialized_data_str, serialized_data_hex_str, serialized_data_hex_str_len);

  // print serialized core message
  printf("Serialized messages: ");
  dump_hex_str(core_message_buf, core_message_expected_len);

  // print core message
  core_message_print(msg, 0);

  // clean up
  free(serialized_data_hex_str);
  free(core_message_buf);
  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_message_with_tx);
  RUN_TEST(test_message_with_tx_serialize);
  RUN_TEST(test_message_with_tagged_data_serialize);

  return UNITY_END();
}
