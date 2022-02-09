// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>

#include "client/api/restful/get_message.h"
#include "core/models/payloads/milestone.h"
#include "core/models/payloads/transaction.h"
#include "test_config.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_msg_by_id() {
  char const* const msg_id = "89e6422b28974940af3e0750790c2a685b296cf29af28565b36cc17436f7fdf2";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_message_t* msg = res_message_new();
  TEST_ASSERT_NOT_NULL(msg);
  TEST_ASSERT(get_message_by_id(&ctx, msg_id, msg) == 0);
  if (msg->is_error) {
    printf("API response: %s\n", msg->u.error->msg);
  } else {
    switch (msg->u.msg->payload_type) {
      case CORE_MESSAGE_PAYLOAD_TRANSACTION:
        printf("it's a transaction message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_INDEXATION:
        printf("it's an indexation message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_MILESTONE:
        printf("it's a milestone message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_UNKNOW:
      default:
        printf("Unknow message\n");
        break;
    }
  }
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
  res_message_t* res = res_message_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_message(ms_res, res) == 0);
  TEST_ASSERT(res->is_error == false);

  core_message_t* msg = res->u.msg;
  TEST_ASSERT_EQUAL_UINT64(9466822412763346725U, msg->network_id);
  TEST_ASSERT_EQUAL_UINT64(10760600709663927622U, msg->nonce);
  TEST_ASSERT_EQUAL_INT(5, core_message_parent_len(msg));
  TEST_ASSERT_EQUAL_MEMORY("7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
                           core_message_get_parent_id(msg, 0), 64);
  TEST_ASSERT_EQUAL_MEMORY("9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
                           core_message_get_parent_id(msg, 1), 64);
  TEST_ASSERT_EQUAL_MEMORY("ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52",
                           core_message_get_parent_id(msg, 2), 64);
  TEST_ASSERT_EQUAL_MEMORY("ede431f8907b30c81eee57db80109af0b8b91683c0be2cc3b685bcdc14dbdca5",
                           core_message_get_parent_id(msg, 3), 64);
  TEST_ASSERT_EQUAL_MEMORY("fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a",
                           core_message_get_parent_id(msg, 4), 64);
  TEST_ASSERT(msg->payload_type == CORE_MESSAGE_PAYLOAD_MILESTONE);

  milestone_t* ms = (milestone_t*)msg->payload;
  TEST_ASSERT(1613651642 == ms->timestamp);
  TEST_ASSERT(123519 == ms->index);
  TEST_ASSERT_EQUAL_MEMORY("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                           ms->inclusion_merkle_proof, 64);
  TEST_ASSERT(2 == milestone_payload_get_signature_count(ms));
  TEST_ASSERT_EQUAL_MEMORY(
      "2ef781713287ba11efd0f3be37a49c2a08a8fdd1099b36e6fb7c9cb290b1711dd4fe08489ecd3872ac663bebebedd27cd73325d53315421d"
      "923b77ffd9ab3b0c",
      milestone_payload_get_signature(ms, 0), MILESTONE_SIGNATURE_HEX_STR_LEN);
  TEST_ASSERT_EQUAL_MEMORY(
      "c42983ce8e619787bbb5aa89cb0987cf08a26a2e4080039614e3c56e766bc86dce50d6e7dc6907edf653e9cc92c89405389fbc71e759c254"
      "fa2aa571a93d850f",
      milestone_payload_get_signature(ms, 1), MILESTONE_SIGNATURE_HEX_STR_LEN);

  milestone_payload_free(ms);
  res_message_free(res);
}

void test_deser_simple_tx() {
  char const* const simple_tx =
      "{\"networkId\":\"8453507715857476362\",\"parentMessageIds\":["
      "\"0875901a61c4b9f2adb37121fc7946d286dae581d1a5f9cd720cb4c1f8d8f552\","
      "\"410653be41fde06bdf25aaeb764cd880f872e33e7ce1759801d75964e9dc75c7\","
      "\"b9130e8d2b928921c220bef325eb9bcad114bdbce80945565e54e8cf9664173a\","
      "\"cf94502e06fab8dcc4ef9fc94721de2e2fcaf727e0998b6489a0a5b5eead6625\"],\"payload\":{\"type\":0,\"essence\":{"
      "\"type\":0,\"inputs\":[{\"type\":0,\"transactionId\":"
      "\"0000000000000000000000000000000000000000000000000000000000000000\",\"transactionOutputIndex\":0}],\"outputs\":"
      "[{\"type\":3,\"amount\":10000000,\"nativeTokens\":[],\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":0,"
      "\"address\":\"21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942\"}}],\"featureBlocks\":[]},{"
      "\"type\":3,\"amount\":2779530273277761,\"nativeTokens\":[],\"unlockConditions\":[{\"type\":0,\"address\":{"
      "\"type\":0,\"address\":\"60200bad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe\"}}],"
      "\"featureBlocks\":[]}],\"payload\":{\"type\":5,\"tag\":\"484f524e455420464155434554\",\"data\":\"\"}},"
      "\"unlockBlocks\":[{\"type\":0,\"signature\":{\"type\":0,\"publicKey\":"
      "\"31f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb\",\"signature\":"
      "\"1b51aab768dd145de99fc3710c7b05963803f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f810a"
      "d0cc4b0210adaafd0a\"}}]},\"nonce\":\"62900\"}";

  res_message_t* res = res_message_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_message(simple_tx, res) == 0);
  TEST_ASSERT(res->is_error == false);

  char str_buff[65] = {};
  // validate network ID
  sprintf(str_buff, "%" PRIu64 "", res->u.msg->network_id);
  TEST_ASSERT_EQUAL_STRING("8453507715857476362", str_buff);

  // TODO: validate parent message IDs
  TEST_ASSERT_EQUAL_INT(4, core_message_parent_len(res->u.msg));

  // TODO: validate payload

  // validate nonce
  sprintf(str_buff, "%" PRIu64 "", res->u.msg->nonce);
  TEST_ASSERT_EQUAL_STRING("62900", str_buff);

  res_message_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_simple_tx);
#if 0  // FIXME
  RUN_TEST(test_deser_milestone);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_msg_by_id);
#endif
#endif
  return UNITY_END();
}
