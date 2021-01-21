// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_message.h"

void test_get_indexation() {
  char const* const msg_id = "e9e7e20cd3a626ea0166324ce202f24a5d3cec464b273ae4b986a188960e5cc2";
  iota_client_conf_t ctx = {
      .url = "https://api.lb-0.testnet.chrysalis2.com/",
      .port = 0  // use default port number
  };

  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(get_message_by_id(&ctx, msg_id, msg) == 0);
  // TEST_ASSERT(msg->is_error == false);
  res_message_free(msg);
}

void test_deser_indexation() {
  char const* const idx_res =
      "{\"data\":{\"networkId\":\"6530425480034647824\",\"parent1MessageId\":"
      "\"f4ec1c1342e2003779e03c6c660315d8b69a0ce8ae60666e9642c4fb79a9c7ee\",\"parent2MessageId\":"
      "\"5c1b3e7ee5012d719ebc423f01f08e9c8812ecf3fb155ceeb931d4265f8faeed\",\"payload\":{\"type\":2,\"index\":\"Foo\","
      "\"data\":\"426172\"},\"nonce\":\"181571\"}}";
  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(deser_get_message(idx_res, msg) == 0);
  TEST_ASSERT(msg->is_error == false);
  TEST_ASSERT_EQUAL_STRING("6530425480034647824", msg->u.msg->net_id);
  TEST_ASSERT_EQUAL_STRING("181571", msg->u.msg->nonce);
  TEST_ASSERT_EQUAL_MEMORY("f4ec1c1342e2003779e03c6c660315d8b69a0ce8ae60666e9642c4fb79a9c7ee", msg->u.msg->parent1, 64);
  TEST_ASSERT_EQUAL_MEMORY("5c1b3e7ee5012d719ebc423f01f08e9c8812ecf3fb155ceeb931d4265f8faeed", msg->u.msg->parent2, 64);
  TEST_ASSERT(msg->u.msg->type == MSG_PAYLOAD_INDEXATION);
  payload_index_t* idx = (payload_index_t*)msg->u.msg->payload;
  TEST_ASSERT_EQUAL_STRING("Foo", idx->index->data);
  TEST_ASSERT_EQUAL_STRING("426172", idx->data->data);

  res_message_free(msg);
}

void test_deser_milestone() {
  char const* const ms_res =
      "{\"data\":{\"networkId\":\"6530425480034647824\",\"parent1MessageId\":"
      "\"40b89f66abe126529ddc058dcbc1ba9f262703032e0d91be014a34e811451840\",\"parent2MessageId\":"
      "\"0e3943b665e47e5bfd019d086c032e12c113e87752ea9a796fafb300ea7a132c\",\"payload\":{\"type\":1,\"index\":2,"
      "\"timestamp\":1605792285,\"inclusionMerkleProof\":"
      "\"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b7"
      "55d56f701afe9be2ce\",\"signatures\":["
      "\"e45035dd125a9baa121ec3e116b9518b424e99aaf791d4944c1ca6d91cf711e3284cb1872995668b60348bce23aa9aebec240c9469687d"
      "3f3b9a72fd948cf50d\","
      "\"aeb862a58ca4a5e83fdad5f1e8a57293137ac0f9b706b4a18af3d1d82618c5752715c83746bd8a405a72304a85918678fffd2df76e9c5e"
      "f41a3f0f5c955e4302\"]},\"nonce\":\"1298542\"}}";
  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(deser_get_message(ms_res, msg) == 0);
  TEST_ASSERT(msg->is_error == false);

  TEST_ASSERT_EQUAL_STRING("6530425480034647824", msg->u.msg->net_id);
  TEST_ASSERT_EQUAL_STRING("1298542", msg->u.msg->nonce);
  TEST_ASSERT_EQUAL_MEMORY("40b89f66abe126529ddc058dcbc1ba9f262703032e0d91be014a34e811451840", msg->u.msg->parent1,
                           sizeof(msg->u.msg->parent1));
  TEST_ASSERT_EQUAL_MEMORY("0e3943b665e47e5bfd019d086c032e12c113e87752ea9a796fafb300ea7a132c", msg->u.msg->parent2,
                           sizeof(msg->u.msg->parent2));
  TEST_ASSERT(msg->u.msg->type == MSG_PAYLOAD_MILESTONE);

  payload_milestone_t* ms = (payload_milestone_t*)msg->u.msg->payload;
  TEST_ASSERT(1605792285 == ms->timestamp);
  TEST_ASSERT(2 == ms->index);
  TEST_ASSERT_EQUAL_MEMORY(
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755"
      "d56f701afe9be2ce",
      ms->inclusion_merkle_proof, 128);
  TEST_ASSERT(2 == get_message_milestone_signature_count(msg));
  TEST_ASSERT_EQUAL_MEMORY(
      "e45035dd125a9baa121ec3e116b9518b424e99aaf791d4944c1ca6d91cf711e3284cb1872995668b60348bce23aa9aebec240c9469687d3f"
      "3b9a72fd948cf50d",
      get_message_milestone_signature(msg, 0), 128);
  TEST_ASSERT_EQUAL_MEMORY(
      "aeb862a58ca4a5e83fdad5f1e8a57293137ac0f9b706b4a18af3d1d82618c5752715c83746bd8a405a72304a85918678fffd2df76e9c5ef4"
      "1a3f0f5c955e4302",
      get_message_milestone_signature(msg, 1), 128);

  res_message_free(msg);
}

void test_deser_transaction() {
  // case 1
  char const* const tx_res1 =
      "{\"data\":{\"networkId\":\"6530425480034647824\",\"parent1MessageId\":"
      "\"b89a14f84e394c39972aa63fde429882658e8c9b720ee3acdb254f8e7c9f97fc\",\"parent2MessageId\":"
      "\"8f812632b44ef780c1054e4d21efcab33f109efc90b2b79ccd7f73afcded551a\",\"payload\":{\"type\":0,\"essence\":{"
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
  TEST_ASSERT_EQUAL_MEMORY("b89a14f84e394c39972aa63fde429882658e8c9b720ee3acdb254f8e7c9f97fc", msg->u.msg->parent1,
                           sizeof(msg->u.msg->parent1));
  TEST_ASSERT_EQUAL_MEMORY("8f812632b44ef780c1054e4d21efcab33f109efc90b2b79ccd7f73afcded551a", msg->u.msg->parent2,
                           sizeof(msg->u.msg->parent2));
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
      "{\"data\":{\"networkId\":\"6530425480034647824\",\"parent1MessageId\":"
      "\"b89a14f84e394c39972aa63fde429882658e8c9b720ee3acdb254f8e7c9f97fc\",\"parent2MessageId\":"
      "\"8f812632b44ef780c1054e4d21efcab33f109efc90b2b79ccd7f73afcded551a\",\"payload\":{\"type\":0,\"essence\":{"
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
  TEST_ASSERT_EQUAL_MEMORY("b89a14f84e394c39972aa63fde429882658e8c9b720ee3acdb254f8e7c9f97fc", msg->u.msg->parent1,
                           sizeof(msg->u.msg->parent1));
  TEST_ASSERT_EQUAL_MEMORY("8f812632b44ef780c1054e4d21efcab33f109efc90b2b79ccd7f73afcded551a", msg->u.msg->parent2,
                           sizeof(msg->u.msg->parent2));
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
