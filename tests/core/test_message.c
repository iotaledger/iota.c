// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "core/address.h"
#include "core/models/message.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/outputs.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "core/models/signing.h"
#include "core/utils/macros.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

static output_basic_t* create_output_basic_one() {
  // create ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, addr.address, ED25519_PUBKEY_BYTES) == 0);

  // create address unlock condition
  unlock_cond_blk_t* addr_unlock_cond = cond_blk_addr_new(&addr);
  TEST_ASSERT_NOT_NULL(addr_unlock_cond);

  // crete unlock conditions list
  cond_blk_list_t* unlock_conditions = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conditions, addr_unlock_cond) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(10000000, NULL, unlock_conditions, NULL);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  cond_blk_free(addr_unlock_cond);
  cond_blk_list_free(unlock_conditions);

  return output;
}

static output_basic_t* create_output_basic_two() {
  // create ed25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("60200bad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, addr.address, ED25519_PUBKEY_BYTES) == 0);

  // create address unlock condition
  unlock_cond_blk_t* addr_unlock_cond = cond_blk_addr_new(&addr);
  TEST_ASSERT_NOT_NULL(addr_unlock_cond);

  // crete unlock conditions list
  cond_blk_list_t* unlock_conditions = cond_blk_list_new();
  TEST_ASSERT(cond_blk_list_add(&unlock_conditions, addr_unlock_cond) == 0);

  // create Basic Output
  output_basic_t* output = output_basic_new(2779530273277761, NULL, unlock_conditions, NULL);
  TEST_ASSERT_NOT_NULL(output);

  // clean up
  cond_blk_free(addr_unlock_cond);
  cond_blk_list_free(unlock_conditions);

  return output;
}

static byte_t* create_signature_unlock_block() {
  byte_t pub_key[ED_PUBLIC_KEY_BYTES] = {};
  TEST_ASSERT(hex_2_bin("31f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb",
                        BIN_TO_HEX_BYTES(ED_PUBLIC_KEY_BYTES), NULL, pub_key, sizeof(pub_key)) == 0);
  byte_t sig[ED_SIGNATURE_BYTES] = {};
  TEST_ASSERT(hex_2_bin("1b51aab768dd145de99fc3710c7b05963803f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e1"
                        "60efc9fe034f810ad0cc4b0210adaafd0a",
                        BIN_TO_HEX_BYTES(ED_SIGNATURE_BYTES), NULL, sig, sizeof(sig)) == 0);

  // create a signature unlock block
  byte_t* signature = malloc(ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_NOT_NULL(signature);

  signature[0] = 0;  // denotes ed25519 signature
  memcpy(signature + 1, pub_key, ED_PUBLIC_KEY_BYTES);
  memcpy(signature + (1 + ED_PUBLIC_KEY_BYTES), sig, ED_SIGNATURE_BYTES);

  return signature;
}

void test_message_with_tx() {
  byte_t expected_essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {
      0x66, 0xbc, 0xeb, 0x49, 0x14, 0x49, 0x6f, 0xf1, 0xb2, 0x21, 0x9a, 0xb5, 0xb3, 0x31, 0x1e, 0xc7,
      0x67, 0x57, 0x89, 0x93, 0x6c, 0x99, 0x84, 0x69, 0xe4, 0xad, 0x1c, 0x3a, 0x85, 0xb0, 0x40, 0xa8};
  byte_t tx_id0[IOTA_TRANSACTION_ID_BYTES] = {126, 127, 95,  249, 151, 44,  243, 150, 40,  39, 46,
                                              190, 54,  49,  73,  171, 165, 88,  139, 221, 25, 199,
                                              90,  172, 252, 142, 91,  179, 113, 2,   177, 58};

  ed25519_keypair_t seed_keypair = {};
  TEST_ASSERT(hex_2_bin("f7868ab6bb55800b77b8b74191ad8285a9bf428ace579d541fda47661803ff44", 64, NULL, seed_keypair.pub,
                        ED_PUBLIC_KEY_BYTES) == 0);
  TEST_ASSERT(
      hex_2_bin("256a818b2aac458941f7274985a410e57fb750f3a3a67969ece5bd9ae7eef5b2f7868ab6bb55800b77b8b74191ad8285"
                "a9bf428ace579d541fda47661803ff44",
                128, NULL, seed_keypair.priv, ED_PRIVATE_KEY_BYTES) == 0);

  // create an address for basic output address unlock condition
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ED25519_PUBKEY_BYTES);

  // create transaction payload
  uint16_t network_id = 2;
  transaction_payload_t* tx = tx_payload_new(network_id);

  // add input with tx_id0
  TEST_ASSERT(tx_essence_add_input(tx->essence, 0, tx_id0, 1) == 0);

  // Create signature data. This data is in real scenario fetched from a node.
  signing_data_list_t* sign_data_list = signing_new();

  TEST_ASSERT(signing_data_add(&addr, NULL, 0, &seed_keypair, &sign_data_list) == 0);

  // add basic output one
  output_basic_t* basic_output_one = create_output_basic_one();
  TEST_ASSERT(tx_essence_add_output(tx->essence, OUTPUT_BASIC, basic_output_one) == 0);

  // add basic output two
  output_basic_t* basic_output_two = create_output_basic_two();
  TEST_ASSERT(tx_essence_add_output(tx->essence, OUTPUT_BASIC, basic_output_two) == 0);

  // create message
  uint8_t protocol_ver = 2;
  core_message_t* msg = core_message_new(protocol_ver);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload = tx;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;

  // calculate transaction essence hash
  byte_t essence_hash[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(core_message_essence_hash_calc(msg, essence_hash, sizeof(essence_hash)) == 0);

  // check if essence hash is matching
  TEST_ASSERT_EQUAL_MEMORY(expected_essence_hash, essence_hash, CRYPTO_BLAKE2B_256_HASH_BYTES);

  // sign transaction (generate unlock blocks)
  TEST_ASSERT(signing_transaction_sign(essence_hash, sizeof(essence_hash), tx->essence->inputs, sign_data_list,
                                       &tx->unlock_blocks) == 0);

  // validate unlock blocks
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(tx->unlock_blocks));

  unlock_block_t* unlock_block = unlock_blocks_get(tx->unlock_blocks, 0);
  TEST_ASSERT(unlock_block->type == UNLOCK_BLOCK_TYPE_SIGNATURE);

  core_message_print(msg, 0);

  // free message and sub entities
  signing_free(sign_data_list);
  output_basic_free(basic_output_one);
  output_basic_free(basic_output_two);
  core_message_free(msg);
}

void test_message_with_tx_serialize() {
  char test_serialized_data_str[] =
      "020432cb4c7602013ba16231fd9bf1bdd9c1b9a403c07dd155ff9979a72684dafdb364463ce32fb6ef011cfff38b736b466f974a92429767"
      "650777cd9b77cf7f26bfe1a518eccfa39a03aeb4b425a51db030eeec1c32654c1c943bc008eb4dc8d862ef8728a24dc0864a94b4f629d8ed"
      "7f56003cf84483700bac919d02622f20dc702f01000006000000010005780242a8ef1e010000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200038096980000"
      "0000000001000021e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942000341c794d2f7df09000001000060200b"
      "ad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe0017000000050000000e484f524e45542046415543455400000000"
      "000100000031f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb1b51aab768dd145de99fc3710c7b05963803f2"
      "8c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f810ad0cc4b0210adaafd0a15af000000000000";

  core_message_t* msg = core_message_new(2);
  TEST_ASSERT_NOT_NULL(msg);

  // add message parents
  byte_t parent_id_1[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("32cb4c7602013ba16231fd9bf1bdd9c1b9a403c07dd155ff9979a72684dafdb3", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_1, sizeof(parent_id_1));
  byte_t parent_id_2[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("64463ce32fb6ef011cfff38b736b466f974a92429767650777cd9b77cf7f26bf", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_2, sizeof(parent_id_2));
  byte_t parent_id_3[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("e1a518eccfa39a03aeb4b425a51db030eeec1c32654c1c943bc008eb4dc8d862", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_3, sizeof(parent_id_3));
  byte_t parent_id_4[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("ef8728a24dc0864a94b4f629d8ed7f56003cf84483700bac919d02622f20dc70", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_4, sizeof(parent_id_4));
  core_message_add_parent(msg, parent_id_1);
  core_message_add_parent(msg, parent_id_2);
  core_message_add_parent(msg, parent_id_3);
  core_message_add_parent(msg, parent_id_4);
  TEST_ASSERT_EQUAL_UINT8(4, core_message_parent_len(msg));

  // add message payload
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;
  msg->payload = tx_payload_new(2229185342034412800);

  // add message nonce
  msg->nonce = 44821;

  // add transaction essence
  transaction_essence_t* essence = ((transaction_payload_t*)msg->payload)->essence;
  TEST_ASSERT_NOT_NULL(essence);

  // add type
  essence->tx_type = TRANSACTION_ESSENCE_TYPE;

  // add input with id0
  byte_t input_id0[IOTA_TRANSACTION_ID_BYTES];
  hex_2_bin("0000000000000000000000000000000000000000000000000000000000000000",
            BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES), NULL, input_id0, sizeof(input_id0));
  TEST_ASSERT(tx_essence_add_input(essence, 0, input_id0, 0) == 0);

  // add basic output one
  output_basic_t* basic_output_one = create_output_basic_one();
  TEST_ASSERT(tx_essence_add_output(essence, OUTPUT_BASIC, basic_output_one) == 0);

  // add basic output two
  output_basic_t* basic_output_two = create_output_basic_two();
  TEST_ASSERT(tx_essence_add_output(essence, OUTPUT_BASIC, basic_output_two) == 0);

  // add tagged data payload
  char const* const hornet_faucet = "HORNET FAUCET";
  tagged_data_payload_t* tagged_data = tagged_data_new((byte_t*)hornet_faucet, strlen(hornet_faucet) + 1, NULL, 0);
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
  bin_2_hex(core_message_buf, core_message_expected_len, NULL, serialized_data_hex_str, serialized_data_hex_str_len);
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
  output_basic_free(basic_output_one);
  output_basic_free(basic_output_two);
  tagged_data_free(tagged_data);
  core_message_free(msg);
}

void test_message_with_tagged_data_serialize() {
  char test_serialized_data_str[] =
      "0204177fc9af60009e4e4e835baf7fe9f5f05aaf9b4e391e605d67cb722bf556266960f767d157c2cfb12533082abb3085a22665ef19f7bf"
      "77a3e39a2b223f33108a6af00016d7fbe8e5aa55c6688db5d5eb4241a562c4bd89ce8e6c0bc3fc3f6458fe53e33c0b95699172a9537f116e"
      "e6a61c2cc153e4f857071bde2f72e23132881f000000050000000b696f74612e63206c6962000b00000048656c6c6f20576f726c6460e600"
      "0000000000";

  core_message_t* msg = core_message_new(2);
  TEST_ASSERT_NOT_NULL(msg);

  // add message parents
  byte_t parent_id_1[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("177fc9af60009e4e4e835baf7fe9f5f05aaf9b4e391e605d67cb722bf5562669", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_1, sizeof(parent_id_1));
  byte_t parent_id_2[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("60f767d157c2cfb12533082abb3085a22665ef19f7bf77a3e39a2b223f33108a", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_2, sizeof(parent_id_2));
  byte_t parent_id_3[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("6af00016d7fbe8e5aa55c6688db5d5eb4241a562c4bd89ce8e6c0bc3fc3f6458", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_3, sizeof(parent_id_3));
  byte_t parent_id_4[IOTA_MESSAGE_ID_BYTES];
  hex_2_bin("fe53e33c0b95699172a9537f116ee6a61c2cc153e4f857071bde2f72e2313288", BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES),
            NULL, parent_id_4, sizeof(parent_id_4));
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
  msg->payload = tagged_data_new((byte_t*)iotac_lib, strlen(iotac_lib) + 1, data, sizeof(data));

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
  bin_2_hex(core_message_buf, core_message_expected_len, NULL, serialized_data_hex_str, serialized_data_hex_str_len);
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
