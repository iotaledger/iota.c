// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "test_config.h"

#include "client/api/restful/get_message.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/get_output.h"
#include "client/api/restful/get_outputs_id.h"
#include "client/api/restful/get_tips.h"
#include "client/api/restful/send_message.h"
#include "core/address.h"
#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/outputs.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "core/models/unlock_block.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

#define TAG_TAG_LEN 15
#define TAG_DATA_LEN 64
char const* const tag = "IOTA TEST DATA";
byte_t binary_tag[TAG_TAG_LEN] = {0x13, 0x94, 0x12, 0xdd, 0x2b, 0xff, 0xd4, 0x55,
                                  0x62, 0x90, 0xfd, 0x6f, 0xa8, 0x30, 0x1f};
byte_t binary_tag_max_len[TAGGED_DATA_TAG_MAX_LENGTH_BYTES] = {
    0x85, 0x59, 0x08, 0x90, 0xbe, 0x39, 0xff, 0xfe, 0x49, 0xab, 0x97, 0x4f, 0x8d, 0x0c, 0x00, 0x35,
    0x63, 0xa3, 0x84, 0x78, 0xc5, 0x22, 0xbc, 0x0d, 0x04, 0xf9, 0xd5, 0xd8, 0xd0, 0xc5, 0x97, 0xe2,
    0x18, 0x6e, 0xa2, 0x53, 0x52, 0xcd, 0x27, 0x4c, 0x6e, 0x9b, 0x0d, 0x54, 0x25, 0xed, 0x7a, 0xb2,
    0xcd, 0x1b, 0x6d, 0x9a, 0x00, 0x7a, 0x25, 0x54, 0x52, 0x9b, 0xdd, 0x35, 0x4c, 0xd2, 0xf8, 0x19};

void setUp(void) {}

void tearDown(void) {}

void test_deser_send_msg_response() {
  char const* const str_res = "{\"messageId\":\"322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5\"}";
  char const* const msg_id = "322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5";
  res_send_message_t res = {};

  TEST_ASSERT(deser_send_message_response(str_res, &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  TEST_ASSERT_EQUAL_STRING(msg_id, res.u.msg_id);
}

void test_send_core_message_tagged_data() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);

  // Create tagged data payload
  tagged_data_t* tagged_data = tagged_data_create((byte_t*)tag, TAG_TAG_LEN, tag_data, TAG_DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_print(tagged_data, 0);

  // Create a core message object
  core_message_t* msg = core_message_new(2);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TAGGED;
  msg->payload = tagged_data;
  msg->nonce = 0;

  res_send_message_t res = {};
  res.is_error = false;

  // Test NULL Input Parameters
  TEST_ASSERT_EQUAL_INT(-1, send_core_message(NULL, msg, &res));
  TEST_ASSERT_EQUAL_INT(-1, send_core_message(&ctx, NULL, &res));
  TEST_ASSERT_EQUAL_INT(-1, send_core_message(&ctx, msg, NULL));

  TEST_ASSERT_EQUAL_INT(0, send_core_message(&ctx, msg, &res));
  TEST_ASSERT(res.is_error == false);

  printf("Message ID: %s\n", res.u.msg_id);
  core_message_free(msg);

  // Get message by message id
  res_message_t* msg_res = res_message_new();
  TEST_ASSERT_NOT_NULL(msg_res);
  TEST_ASSERT_EQUAL_INT(0, get_message_by_id(&ctx, res.u.msg_id, msg_res));

  // Get tagged data payload from message response
  tagged_data_t* tagged_data_res = (tagged_data_t*)msg_res->u.msg->payload;

  // Check if tag in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->tag->data, (byte_t*)tag, TAG_TAG_LEN);

  // Check if data in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->data->data, tag_data, TAG_DATA_LEN);
  res_message_free(msg_res);
}

void test_send_core_message_tagged_data_binary_tag() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);

  // Create tagged data payload
  tagged_data_t* tagged_data = tagged_data_create(binary_tag, TAG_TAG_LEN, tag_data, TAG_DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_print(tagged_data, 0);

  // Create a core message object
  core_message_t* msg = core_message_new(2);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TAGGED;
  msg->payload = tagged_data;
  msg->nonce = 0;

  res_send_message_t res = {};
  res.is_error = false;

  TEST_ASSERT_EQUAL_INT(0, send_core_message(&ctx, msg, &res));
  TEST_ASSERT(res.is_error == false);

  printf("Message ID: %s\n", res.u.msg_id);
  core_message_free(msg);

  // Get message by message id
  res_message_t* msg_res = res_message_new();
  TEST_ASSERT_NOT_NULL(msg_res);
  TEST_ASSERT_EQUAL_INT(0, get_message_by_id(&ctx, res.u.msg_id, msg_res));

  // Get tagged data payload from message response
  tagged_data_t* tagged_data_res = (tagged_data_t*)msg_res->u.msg->payload;

  // Check if tag in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->tag->data, binary_tag, TAG_TAG_LEN);

  // Check if data in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->data->data, tag_data, TAG_DATA_LEN);
  res_message_free(msg_res);
}

void test_send_core_message_tagged_data_tag_max_len() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t tag_data[TAG_DATA_LEN];
  iota_crypto_randombytes(tag_data, TAG_DATA_LEN);

  // Create tagged data payload
  tagged_data_t* tagged_data =
      tagged_data_create(binary_tag_max_len, TAGGED_DATA_TAG_MAX_LENGTH_BYTES, tag_data, TAG_DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_print(tagged_data, 0);

  // Create a core message object
  core_message_t* msg = core_message_new(2);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TAGGED;
  msg->payload = tagged_data;
  msg->nonce = 0;

  res_send_message_t res = {};
  res.is_error = false;

  TEST_ASSERT_EQUAL_INT(0, send_core_message(&ctx, msg, &res));
  TEST_ASSERT(res.is_error == false);

  printf("Message ID: %s\n", res.u.msg_id);
  core_message_free(msg);

  // Get message by message id
  res_message_t* msg_res = res_message_new();
  TEST_ASSERT_NOT_NULL(msg_res);
  TEST_ASSERT_EQUAL_INT(0, get_message_by_id(&ctx, res.u.msg_id, msg_res));

  // Get tagged data payload from message response
  tagged_data_t* tagged_data_res = (tagged_data_t*)msg_res->u.msg->payload;

  // Check if tag in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->tag->data, binary_tag_max_len, TAGGED_DATA_TAG_MAX_LENGTH_BYTES);

  // Check if data in the tagged data payload matches
  TEST_ASSERT_EQUAL_MEMORY(tagged_data_res->data->data, tag_data, TAG_DATA_LEN);
  res_message_free(msg_res);
}

void test_send_msg_tx_extended() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  // mnemonic seed for testing
  byte_t mnemonic_seed[64] = {0x83, 0x7D, 0x69, 0x91, 0x14, 0x64, 0x8E, 0xB,  0x36, 0x78, 0x58, 0xF0, 0xE9,
                              0xA8, 0x4E, 0xF8, 0xBD, 0xFF, 0xD,  0xB7, 0x71, 0x4A, 0xD6, 0x3A, 0xA9, 0x52,
                              0x32, 0x43, 0x56, 0xB6, 0x53, 0x65, 0xD0, 0xE3, 0x9A, 0x30, 0x3A, 0xC5, 0xBB,
                              0xAE, 0x83, 0xD0, 0x13, 0xBC, 0x76, 0xB6, 0xC5, 0xE6, 0xFD, 0xCD, 0x2E, 0x72,
                              0xEC, 0x80, 0x41, 0x33, 0xF3, 0x7B, 0xC0, 0x3E, 0x2A, 0x35, 0xC4, 0xA9};

  // get address from mnemonic seed
  address_t addr_send, addr_recv;
  ed25519_keypair_t sender_key = {};
  char bech32_sender[65] = {};
  char bech32_receiver[65] = {};
  // IOTA BIP44 Paths: m/44'/4128'/Account'/Change'/Index'
  TEST_ASSERT(address_keypair_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/0'", &sender_key) ==
              0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/0'", &addr_send) == 0);
  TEST_ASSERT(ed25519_address_from_path(mnemonic_seed, sizeof(mnemonic_seed), "m/44'/4218'/0'/0'/1'", &addr_recv) == 0);

  char const* const hrp = "atoi";
  address_to_bech32(&addr_send, hrp, bech32_sender, sizeof(bech32_sender));
  address_to_bech32(&addr_recv, hrp, bech32_receiver, sizeof(bech32_receiver));
  printf("sender: %s\nreceiver: %s\n", bech32_sender, bech32_receiver);

  // Get info from a node and set correct network ID in protocol version
  res_node_info_t* info = res_node_info_new();
  int ret = get_node_info(&ctx, info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);

  // Set correct protocol version and network ID
  uint8_t ver = info->u.output_node_info->protocol_version;
  uint8_t network_id_hash[CRYPTO_BLAKE2B_HASH_BYTES];
  uint64_t network_id;
  iota_blake2b_sum((const uint8_t*)info->u.output_node_info->network_name,
                   strlen(info->u.output_node_info->network_name), network_id_hash, sizeof(network_id_hash));
  res_node_info_free(info);
  memcpy(&network_id, network_id_hash, sizeof(network_id));

  transaction_payload_t* tx = tx_payload_new(network_id);
  TEST_ASSERT_NOT_NULL(tx);

  // get outputs from an address
  uint64_t send_amount = 1000000;  // send out 1Mi
  res_outputs_id_t* res = res_outputs_new();
  TEST_ASSERT_NOT_NULL(res);
  outputs_query_list_t* query_param = outputs_query_list_new();
  TEST_ASSERT_NULL(query_param);
  outputs_query_list_add(&query_param, QUERY_PARAM_ADDRESS, bech32_sender);
  TEST_ASSERT(get_outputs_id(&ctx, query_param, res) == 0);
  TEST_ASSERT(res_outputs_output_id_count(res) > 0);

  // dump outputs for debugging
  // for (size_t i = 0; i < res_outputs_output_id_count(res); i++) {
  //   printf("output[%zu]: %s\n", i, res_outputs_output_id(res, i));
  // }

  // fetch output data from output IDs
  uint64_t total_balance = 0;
  for (size_t i = 0; i < res_outputs_output_id_count(res); i++) {
    res_output_t* output_res = get_output_response_new();
    printf("fetch output: %s\n", res_outputs_output_id(res, i));
    TEST_ASSERT(get_output(&ctx, res_outputs_output_id(res, i), output_res) == 0);
    if (!output_res->is_error) {
      if (output_res->u.data->output->output_type == OUTPUT_EXTENDED) {
        output_extended_t* o = (output_extended_t*)output_res->u.data->output->output;
        total_balance += o->amount;
        // add the output as a tx input into the tx payload
        tx_payload_add_input(tx, 0, output_res->u.data->tx_id, output_res->u.data->output_index, &sender_key);
        // check balance
        if (total_balance >= send_amount) {
          // have got sufficient amount
          get_output_response_free(output_res);
          break;
        }
      }
    } else {
      printf("%s\n", output_res->u.error->msg);
    }
    get_output_response_free(output_res);
  }

  // not used any more
  outputs_query_list_free(query_param);
  res_outputs_free(res);

  // check balance of sender outputs
  TEST_ASSERT(total_balance >= send_amount);

  // receiver output
  unlock_cond_blk_t* b = cond_blk_addr_new(&addr_recv);
  cond_blk_list_t* recv_cond = cond_blk_list_new();
  cond_blk_list_add(&recv_cond, b);
  output_extended_t* recv_output = output_extended_new(send_amount, NULL, recv_cond, NULL);
  // add receiver output to tx payload
  tx_payload_add_output(tx, OUTPUT_EXTENDED, recv_output);
  cond_blk_free(b);
  cond_blk_list_free(recv_cond);
  output_extended_free(recv_output);

  // if remainder is needed?
  if (total_balance > send_amount) {
    // remainder output
    b = cond_blk_addr_new(&addr_send);
    cond_blk_list_t* remainder_cond = cond_blk_list_new();
    cond_blk_list_add(&remainder_cond, b);
    output_extended_t* remainder_output = output_extended_new(total_balance - send_amount, NULL, remainder_cond, NULL);
    TEST_ASSERT_NOT_NULL(remainder_output);
    // add receiver output to output list
    tx_payload_add_output(tx, OUTPUT_EXTENDED, remainder_output);
    cond_blk_free(b);
    cond_blk_list_free(remainder_cond);
    output_extended_free(remainder_output);
  }

  // add transaction payload to message
  core_message_t* msg = core_message_new(ver);
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload = tx;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;
  TEST_ASSERT(core_message_sign_transaction(msg) == 0);

  // send out message
  res_send_message_t send_msg_res = {};
  TEST_ASSERT(send_core_message(&ctx, msg, &send_msg_res) == 0);
  // dump message object on terminal
  core_message_print(msg, 0);
  if (send_msg_res.is_error) {
    printf("Error: %s\n", send_msg_res.u.error->msg);
  } else {
    printf("message ID: %s\n", send_msg_res.u.msg_id);
  }

  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_send_msg_response);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_send_core_message_tagged_data);
  RUN_TEST(test_send_core_message_tagged_data_binary_tag);
  RUN_TEST(test_send_core_message_tagged_data_tag_max_len);
  RUN_TEST(test_send_msg_tx_extended);
#endif

  return UNITY_END();
}
