// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"

#include "client/api/v1/get_output.h"
#include "client/api/v1/get_outputs_from_address.h"
#include "client/api/v1/send_message.h"
#include "core/utils/byte_buffer.h"

#include "core/address.h"

void setUp(void) {}

void tearDown(void) {}

void test_send_indexation() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_send_message_t res = {};
  TEST_ASSERT(send_indexation_msg(&ctx, "iota.c", "Hello IOTA", &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  printf("message ID: %s\n", res.u.msg_id);
}

void test_send_core_message_indexation() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  byte_t idx_data[12] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
  indexation_t* idx = indexation_create("iota.c", idx_data, sizeof(idx_data));
  TEST_ASSERT_NOT_NULL(idx);
  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = 2;
  msg->payload = idx;

  res_send_message_t res = {};
  TEST_ASSERT(send_core_message(&ctx, msg, &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  printf("message ID: %s\n", res.u.msg_id);

  core_message_free(msg);
}

void test_serialize_indexation() {
  char const* const p1 = "7f471d9bb0985e114d78489cfbaf1fb3896931bdc03c89935bacde5b9fbc86ff";
  char const* const p2 = "3b4354521ade76145b5616a414fa283fcdb7635ee627a42ecb2f75135e18f10f";
  char const* const data = "Hello";
  char const* const index = "iota.c";
  char const* const exp_msg =
      "{\"networkId\":\"\",\"parentMessageIds\":[\"7f471d9bb0985e114d78489cfbaf1fb3896931bdc03c89935bacde5b9fbc86ff\","
      "\"3b4354521ade76145b5616a414fa283fcdb7635ee627a42ecb2f75135e18f10f\"],\"payload\":{\"type\":2,\"index\":"
      "\"696F74612E63\",\"data\":\"48656C6C6F\"},\"nonce\":\"\"}";

  message_t* msg = api_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  payload_index_t* idx = payload_index_new();
  TEST_ASSERT_NOT_NULL(idx);
  TEST_ASSERT_TRUE(byte_buf_append(idx->data, (byte_t const*)data, strlen(data) + 1));
  TEST_ASSERT_TRUE(byte_buf_append(idx->index, (byte_t const*)index, strlen(index) + 1));
  msg->type = MSG_PAYLOAD_INDEXATION;
  msg->payload = idx;

  api_message_add_parent(msg, p1);
  api_message_add_parent(msg, p2);
  TEST_ASSERT_EQUAL_INT(2, api_message_parent_count(msg));

  byte_buf_t* message_string = byte_buf_new();
  TEST_ASSERT_NOT_NULL(message_string);
  TEST_ASSERT(serialize_indexation(msg, message_string) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_msg, message_string->data);

  api_message_free(msg);
  byte_buf_free(message_string);
}

void test_deser_send_msg_response() {
  char const* const str_res =
      "{\"data\":{\"messageId\":\"322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5\"}}";
  char const* const exp_id = "322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5";
  res_send_message_t res = {};

  TEST_ASSERT(deser_send_message_response(str_res, &res) == 0);
  TEST_ASSERT_FALSE(res.is_error);
  TEST_ASSERT_EQUAL_STRING(exp_id, res.u.msg_id);
}

// send transaction on alphanet
void test_send_core_message_tx() {
  iota_client_conf_t ctx = {
      .host = "localhost",
      .port = 14265  // use default port number
  };

  byte_t wallet_addr[ED25519_ADDRESS_BYTES] = {0x51, 0x55, 0x82, 0xfe, 0x64, 0x8b, 0x0f, 0x10, 0xa2, 0xb2, 0xa1,
                                               0xb9, 0x1d, 0x75, 0x02, 0x19, 0x0c, 0x97, 0x9b, 0xaa, 0xbf, 0xee,
                                               0x85, 0xb6, 0xbb, 0xb5, 0x02, 0x06, 0x92, 0xe5, 0x5d, 0x16};
  iota_keypair_t genesis_seed_keypair = {};
  TEST_ASSERT(hex_2_bin("f7868ab6bb55800b77b8b74191ad8285a9bf428ace579d541fda47661803ff44", 64,
                        genesis_seed_keypair.pub, ED_PUBLIC_KEY_BYTES) == 0);
  TEST_ASSERT(
      hex_2_bin("256a818b2aac458941f7274985a410e57fb750f3a3a67969ece5bd9ae7eef5b2f7868ab6bb55800b77b8b74191ad8285"
                "a9bf428ace579d541fda47661803ff44",
                128, genesis_seed_keypair.priv, ED_PRIVATE_KEY_BYTES) == 0);

  byte_t genesis_addr[ED25519_ADDRESS_BYTES] = {};
  // address of genesis seed from ed25519
  address_from_ed25519_pub(genesis_seed_keypair.pub, genesis_addr);
  printf("genesis address: ");
  dump_hex_str(genesis_addr, ED25519_ADDRESS_BYTES);
  printf("wallet address: ");
  dump_hex_str(wallet_addr, ED25519_ADDRESS_BYTES);

  // compose transaction payload
  transaction_payload_t* tx_payload = tx_payload_new();
  TEST_ASSERT_NOT_NULL(tx_payload);

  // get outputs
  res_outputs_address_t* res = res_outputs_address_new();
  TEST_ASSERT_NOT_NULL(res);
  int ret = get_outputs_from_address(&ctx, "6920b176f613ec7be59e68fc68f597eb3393af80f74c7c3db78198147d5f1f92", res);
  TEST_ASSERT(ret == 0);
  TEST_ASSERT(res->is_error == false);
  TEST_ASSERT_EQUAL_STRING("6920b176f613ec7be59e68fc68f597eb3393af80f74c7c3db78198147d5f1f92",
                           res->u.output_ids->address);

  size_t out_counts = res_outputs_address_output_id_count(res);
  // get outputs and tx id and tx output index from genesis
  uint64_t total = 0;
  for (size_t i = 0; i < out_counts; i++) {
    char* output_id = res_outputs_address_output_id(res, i);
    res_output_t res_out = {};
    TEST_ASSERT(get_output(&ctx, output_id, &res_out) == 0);
    if (res_out.is_error) {
      res_err_free(res_out.u.error);
      printf("fetch output error!\n");
    }

    // add input to transaction essence
    if (!res_out.u.output.is_spent) {
      if (res_out.u.output.address_type == ADDRESS_VER_ED25519) {
        byte_t tx_id[TRANSACTION_ID_BYTES] = {};
        hex_2_bin(res_out.u.output.tx_id, TRANSACTION_ID_BYTES * 2, tx_id, sizeof(tx_id));
        tx_payload_add_input_with_key(tx_payload, tx_id, res_out.u.output.output_idx, genesis_seed_keypair.pub,
                                      genesis_seed_keypair.priv);
        total += res_out.u.output.amount;
      } else {
        printf("Unknow address type\n");
      }
    }
  }

  // no needed
  res_outputs_address_free(res);

  // create output for sending 10Mi out
  uint64_t token_send = 10000000;
  TEST_ASSERT(tx_payload_add_output(tx_payload, OUTPUT_SINGLE_OUTPUT, wallet_addr, token_send) == 0);
  TEST_ASSERT(tx_payload_add_output(tx_payload, OUTPUT_SINGLE_OUTPUT, genesis_addr, total - token_send) == 0);

  // add indexation to tx payload
  byte_t idx_data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
  TEST_ASSERT(tx_essence_add_payload(tx_payload->essence, 2,
                                     (void*)indexation_create("iota.c", idx_data, sizeof(idx_data))) == 0);

  // create message and put tx payload in message
  core_message_t* msg = core_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  msg->payload_type = 0;
  msg->payload = tx_payload;

  // sign transactions
  TEST_ASSERT(core_message_sign_transaction(msg) == 0);

  // send message
  res_send_message_t msg_res = {};
  TEST_ASSERT(send_core_message(&ctx, msg, &msg_res) == 0);
  TEST_ASSERT_FALSE(msg_res.is_error);
  printf("message ID: %s\n", msg_res.u.msg_id);

  core_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_serialize_indexation);
  RUN_TEST(test_deser_send_msg_response);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_send_indexation);
  RUN_TEST(test_send_core_message_indexation);
#endif
  // send transaction on alphanet
  // RUN_TEST(test_send_core_message_tx);

  return UNITY_END();
}
