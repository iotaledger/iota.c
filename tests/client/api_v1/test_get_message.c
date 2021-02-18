// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_message.h"

void test_get_indexation() {
  char const* const msg_id = "7c58a5bab90219de0231293f40ff65ee7d42e64ae917cc5560f7becdcf6cb158";
  iota_client_conf_t ctx = {
      .url = "https://api.lb-0.testnet.chrysalis2.com/",
      .port = 0  // use default port number
  };

  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(get_message_by_id(&ctx, msg_id, msg) == 0);
  TEST_ASSERT(msg->is_error == false);
  res_message_free(msg);
}

void test_deser_indexation() {
  char const* const idx_res =
      "{\"data\":{\"networkId\":\"9466822412763346725\",\"parentMessageIds\":["
      "\"4f73928a39988fe2d1d15b4aa161c6ba0a64e4d164c481f4cc67c51e316c034e\","
      "\"84cd7f307aecc96fe070a701fae586c95736a9dd6fee18df5319da422575f0f7\","
      "\"aea5b8d4844574a8b0b30d4796523d9012d10fdb32347145172a73a51fc9ed9d\","
      "\"f3b616c2669da3f3fbbafc56fb83213d58238e4a4504d360500b9c6f0c78738c\"],\"payload\":{\"type\":2,\"index\":"
      "\"Foo\",\"data\":"
      "\"426172\"},\"nonce\":\"567803\"}}";
  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(deser_get_message(idx_res, msg) == 0);
  TEST_ASSERT(msg->is_error == false);
  TEST_ASSERT_EQUAL_STRING("9466822412763346725", msg->u.msg->net_id);
  TEST_ASSERT_EQUAL_STRING("567803", msg->u.msg->nonce);
  TEST_ASSERT_EQUAL_INT(4, api_message_parent_count(msg->u.msg));
  TEST_ASSERT_EQUAL_MEMORY("4f73928a39988fe2d1d15b4aa161c6ba0a64e4d164c481f4cc67c51e316c034e",
                           api_message_parent_id(msg->u.msg, 0), 64);
  TEST_ASSERT_EQUAL_MEMORY("84cd7f307aecc96fe070a701fae586c95736a9dd6fee18df5319da422575f0f7",
                           api_message_parent_id(msg->u.msg, 1), 64);
  TEST_ASSERT_EQUAL_MEMORY("aea5b8d4844574a8b0b30d4796523d9012d10fdb32347145172a73a51fc9ed9d",
                           api_message_parent_id(msg->u.msg, 2), 64);
  TEST_ASSERT_EQUAL_MEMORY("f3b616c2669da3f3fbbafc56fb83213d58238e4a4504d360500b9c6f0c78738c",
                           api_message_parent_id(msg->u.msg, 3), 64);
  TEST_ASSERT(msg->u.msg->type == MSG_PAYLOAD_INDEXATION);
  payload_index_t* idx = (payload_index_t*)msg->u.msg->payload;
  TEST_ASSERT_EQUAL_STRING("Foo", idx->index->data);
  TEST_ASSERT_EQUAL_STRING("426172", idx->data->data);

  res_message_free(msg);
}

void test_deser_milestone() {
  char const* const ms_res =
      "{\"data\":{\"networkId\":\"9466822412763346725\",\"parentMessageIds\":["
      "\"7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3\","
      "\"9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c\","
      "\"ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52\","
      "\"ede431f8907b30c81eee57db80109af0b8b91683c0be2cc3b685bcdc14dbdca5\","
      "\"fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a\"],\"payload\":{\"type\":1,\"index\":123519,"
      "\"timestamp\":1613651642,\"parentMessageIds\":["
      "\"7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3\","
      "\"9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c\","
      "\"ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52\","
      "\"ede431f8907b30c81eee57db80109af0b8b91683c0be2cc3b685bcdc14dbdca5\","
      "\"fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a\"],\"inclusionMerkleProof\":"
      "\"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8\",\"publicKeys\":["
      "\"7205c145525cee64f1c9363696811d239919d830ad964b4e29359e6475848f5a\","
      "\"e468e82df33d10dea3bd0eadcd7867946a674d207c39f5af4cc44365d268a7e6\"],\"receipt\":null,\"signatures\":["
      "\"2ef781713287ba11efd0f3be37a49c2a08a8fdd1099b36e6fb7c9cb290b1711dd4fe08489ecd3872ac663bebebedd27cd73325d5331542"
      "1d923b77ffd9ab3b0c\","
      "\"c42983ce8e619787bbb5aa89cb0987cf08a26a2e4080039614e3c56e766bc86dce50d6e7dc6907edf653e9cc92c89405389fbc71e759c2"
      "54fa2aa571a93d850f\"]},\"nonce\":\"10760600709663927622\"}}";
  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(deser_get_message(ms_res, msg) == 0);
  TEST_ASSERT(msg->is_error == false);

  TEST_ASSERT_EQUAL_STRING("9466822412763346725", msg->u.msg->net_id);
  TEST_ASSERT_EQUAL_STRING("10760600709663927622", msg->u.msg->nonce);
  TEST_ASSERT_EQUAL_INT(5, api_message_parent_count(msg->u.msg));
  TEST_ASSERT_EQUAL_MEMORY("7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
                           api_message_parent_id(msg->u.msg, 0), 64);
  TEST_ASSERT_EQUAL_MEMORY("9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
                           api_message_parent_id(msg->u.msg, 1), 64);
  TEST_ASSERT_EQUAL_MEMORY("ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52",
                           api_message_parent_id(msg->u.msg, 2), 64);
  TEST_ASSERT_EQUAL_MEMORY("ede431f8907b30c81eee57db80109af0b8b91683c0be2cc3b685bcdc14dbdca5",
                           api_message_parent_id(msg->u.msg, 3), 64);
  TEST_ASSERT_EQUAL_MEMORY("fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a",
                           api_message_parent_id(msg->u.msg, 4), 64);
  TEST_ASSERT(msg->u.msg->type == MSG_PAYLOAD_MILESTONE);

  payload_milestone_t* ms = (payload_milestone_t*)msg->u.msg->payload;
  TEST_ASSERT(1613651642 == ms->timestamp);
  TEST_ASSERT(123519 == ms->index);
  TEST_ASSERT_EQUAL_MEMORY("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                           ms->inclusion_merkle_proof, 64);
  TEST_ASSERT(2 == get_message_milestone_signature_count(msg));
  TEST_ASSERT_EQUAL_MEMORY(
      "2ef781713287ba11efd0f3be37a49c2a08a8fdd1099b36e6fb7c9cb290b1711dd4fe08489ecd3872ac663bebebedd27cd73325d53315421d"
      "923b77ffd9ab3b0c",
      get_message_milestone_signature(msg, 0), 128);
  TEST_ASSERT_EQUAL_MEMORY(
      "c42983ce8e619787bbb5aa89cb0987cf08a26a2e4080039614e3c56e766bc86dce50d6e7dc6907edf653e9cc92c89405389fbc71e759c254"
      "fa2aa571a93d850f",
      get_message_milestone_signature(msg, 1), 128);

  res_message_free(msg);
}

void test_deser_transaction() {
  // case 1
  char const* const tx_res1 =
      "{\"data\":{\"networkId\":\"6530425480034647824\",\"parentMessageIds\":["
      "\"7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3\","
      "\"9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c\","
      "\"ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52\","
      "\"ede431f8907b30c81eee57db80109af0b8b91683c0be2cc3b685bcdc14dbdca5\"],\"payload\":{\"type\":0,\"essence\":{"
      "\"type\":0,\"inputs\":[{\"type\":0,\"transactionId\":"
      "\"2bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03\",\"transactionOutputIndex\":0}],\"outputs\":"
      "[{\"type\":0,\"address\":{\"type\":1,\"address\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"},\"amount\":1000}],\"payload\":null},"
      "\"unlockBlocks\":[{\"type\":0,\"signature\":{\"type\":1,\"publicKey\":"
      "\"dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a\",\"signature\":"
      "\"e625a71351bbccf87eeaad7e98f6a545306423b2aaf444792a1be8ccfdfe50b358583483c3dbc536b5842eeec381750c6b4495c14932be"
      "47c439a1a8ad242606\"}}]},\"nonce\":\"6416754\"}}";
  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(deser_get_message(tx_res1, msg) == 0);
  TEST_ASSERT(msg->is_error == false);

  TEST_ASSERT_EQUAL_STRING("6530425480034647824", msg->u.msg->net_id);
  TEST_ASSERT_EQUAL_STRING("6416754", msg->u.msg->nonce);
  TEST_ASSERT_EQUAL_INT(4, api_message_parent_count(msg->u.msg));
  TEST_ASSERT_EQUAL_MEMORY("7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
                           api_message_parent_id(msg->u.msg, 0), 64);
  TEST_ASSERT_EQUAL_MEMORY("9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
                           api_message_parent_id(msg->u.msg, 1), 64);
  TEST_ASSERT_EQUAL_MEMORY("ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52",
                           api_message_parent_id(msg->u.msg, 2), 64);
  TEST_ASSERT_EQUAL_MEMORY("ede431f8907b30c81eee57db80109af0b8b91683c0be2cc3b685bcdc14dbdca5",
                           api_message_parent_id(msg->u.msg, 3), 64);
  TEST_ASSERT(get_message_payload_type(msg) == MSG_PAYLOAD_TRANSACTION);

  payload_tx_t* tx = (payload_tx_t*)msg->u.msg->payload;
  // validate input transaction ID and transaction output index
  TEST_ASSERT_EQUAL_UINT32(1, payload_tx_inputs_count(tx));
  TEST_ASSERT_EQUAL_MEMORY("2bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03",
                           payload_tx_inputs_tx_id(tx, 0), 64);
  TEST_ASSERT_EQUAL_UINT32(0, payload_tx_inputs_tx_output_index(tx, 0));
  TEST_ASSERT_NULL(payload_tx_inputs_tx_id(tx, 1));

  // validate output address and amount
  TEST_ASSERT_EQUAL_UINT32(1, payload_tx_outputs_count(tx));
  TEST_ASSERT_EQUAL_MEMORY("ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4",
                           payload_tx_outputs_address(tx, 0), 64);
  TEST_ASSERT(1000 == payload_tx_outputs_amount(tx, 0));

  // validate unlocked block
  TEST_ASSERT_EQUAL_UINT32(1, payload_tx_blocks_count(tx));
  TEST_ASSERT_EQUAL_MEMORY("dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a",
                           payload_tx_blocks_public_key(tx, 0), 64);
  TEST_ASSERT_EQUAL_MEMORY(
      "e625a71351bbccf87eeaad7e98f6a545306423b2aaf444792a1be8ccfdfe50b358583483c3dbc536b5842eeec381750c6b4495c14932be47"
      "c439a1a8ad242606",
      payload_tx_blocks_signature(tx, 0), 128);

  res_message_free(msg);
  msg = NULL;

  // case 2
  char const* const tx_res2 =
      "{\"data\":{\"networkId\":\"6530425480034647824\",\"parentMessageIds\":["
      "\"7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3\","
      "\"9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c\","
      "\"fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a\"],\"payload\":{\"type\":0,\"essence\":{"
      "\"type\":0,\"inputs\":[{\"type\":0,\"transactionId\":"
      "\"2bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03\",\"transactionOutputIndex\":0},{\"type\":0,"
      "\"transactionId\":\"0bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03\","
      "\"transactionOutputIndex\":1}],\"outputs\":[{\"type\":0,\"address\":{\"type\":1,\"address\":"
      "\"ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4\"},\"amount\":1000},{\"type\":0,\"address\":{"
      "\"type\":1,\"address\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"amount\":5000}],"
      "\"payload\":null},\"unlockBlocks\":[{\"type\":0,\"signature\":{\"type\":1,\"publicKey\":"
      "\"dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a\",\"signature\":"
      "\"e625a71351bbccf87eeaad7e98f6a545306423b2aaf444792a1be8ccfdfe50b358583483c3dbc536b5842eeec381750c6b4495c14932be"
      "47c439a1a8ad242606\"}},{\"type\":0,\"signature\":{\"type\":1,\"publicKey\":"
      "\"dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a\",\"signature\":"
      "\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000\"}}]},\"nonce\":\"6416754\"}}";

  msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(deser_get_message(tx_res2, msg) == 0);
  TEST_ASSERT(msg->is_error == false);

  TEST_ASSERT_EQUAL_STRING("6530425480034647824", msg->u.msg->net_id);
  TEST_ASSERT_EQUAL_STRING("6416754", msg->u.msg->nonce);
  TEST_ASSERT_EQUAL_INT(3, api_message_parent_count(msg->u.msg));
  TEST_ASSERT_EQUAL_MEMORY("7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
                           api_message_parent_id(msg->u.msg, 0), 64);
  TEST_ASSERT_EQUAL_MEMORY("9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
                           api_message_parent_id(msg->u.msg, 1), 64);
  TEST_ASSERT_EQUAL_MEMORY("fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a",
                           api_message_parent_id(msg->u.msg, 2), 64);
  TEST_ASSERT(get_message_payload_type(msg) == MSG_PAYLOAD_TRANSACTION);

  tx = (payload_tx_t*)msg->u.msg->payload;
  // validate input transaction ID and transaction output index
  TEST_ASSERT_EQUAL_UINT32(2, payload_tx_inputs_count(tx));
  TEST_ASSERT_EQUAL_MEMORY("2bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03",
                           payload_tx_inputs_tx_id(tx, 0), 64);
  TEST_ASSERT_EQUAL_UINT32(0, payload_tx_inputs_tx_output_index(tx, 0));
  TEST_ASSERT_NOT_NULL(payload_tx_inputs_tx_id(tx, 1));
  TEST_ASSERT_EQUAL_MEMORY("0bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03",
                           payload_tx_inputs_tx_id(tx, 1), 64);
  TEST_ASSERT_EQUAL_UINT32(1, payload_tx_inputs_tx_output_index(tx, 1));

  // validate output address and amount
  TEST_ASSERT_EQUAL_UINT32(2, payload_tx_outputs_count(tx));
  TEST_ASSERT_EQUAL_MEMORY("0000000000000000000000000000000000000000000000000000000000000000",
                           payload_tx_outputs_address(tx, 1), 64);
  TEST_ASSERT(5000 == payload_tx_outputs_amount(tx, 1));

  // validate unlocked block
  TEST_ASSERT_EQUAL_UINT32(2, payload_tx_blocks_count(tx));
  TEST_ASSERT_EQUAL_MEMORY("dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a",
                           payload_tx_blocks_public_key(tx, 1), 64);
  TEST_ASSERT_EQUAL_MEMORY(
      "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000",
      payload_tx_blocks_signature(tx, 1), 128);

  res_message_free(msg);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_indexation);
  RUN_TEST(test_deser_milestone);
  RUN_TEST(test_deser_transaction);
  // RUN_TEST(test_get_indexation);

  return UNITY_END();
}
