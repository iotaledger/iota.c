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
      case CORE_MESSAGE_PAYLOAD_RECEIPT:
        printf("it's a receipt message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_TREASURY:
        printf("it's a treasury message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_TAGGED:
        printf("it's a tagged message\n");
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
      "{\"networkId\":\"8453507715857476362\",\"parentMessageIds\":["
      "\"708300963297a4bec3fac378d24d4c4585ea69216f32dba010d6d8546942f8f6\","
      "\"70c6523d1d1b6cc8b7b8333df31027f608f97ff1681478622b1e7c1852416e61\","
      "\"862038e86f431f6727a5dd06db0cd05689b879fd4f6a9219afef90eddf1141db\","
      "\"94d6b7d3e09476b72a7a2d814e82132acafb7f9b71c519cca1086cbb88fdac01\","
      "\"ba156f10e9af17e49b87fd9dbc42ccaee514855016a6818afa0e839a32e2f2d4\","
      "\"ed6befb669e0c760957939b70fb19996eef043a2742e60c5b08275c62b911b0f\"],\"payload\":{\"type\":1,\"index\":3,"
      "\"timestamp\":1644487067,\"parentMessageIds\":["
      "\"708300963297a4bec3fac378d24d4c4585ea69216f32dba010d6d8546942f8f6\","
      "\"70c6523d1d1b6cc8b7b8333df31027f608f97ff1681478622b1e7c1852416e61\","
      "\"862038e86f431f6727a5dd06db0cd05689b879fd4f6a9219afef90eddf1141db\","
      "\"94d6b7d3e09476b72a7a2d814e82132acafb7f9b71c519cca1086cbb88fdac01\","
      "\"ba156f10e9af17e49b87fd9dbc42ccaee514855016a6818afa0e839a32e2f2d4\","
      "\"ed6befb669e0c760957939b70fb19996eef043a2742e60c5b08275c62b911b0f\"],\"inclusionMerkleProof\":"
      "\"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8\",\"nextPoWScore\":0,"
      "\"nextPoWScoreMilestoneIndex\":0,\"publicKeys\":["
      "\"ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c\","
      "\"f6752f5f46a53364e2ee9c4d662d762a81efd51010282a75cd6bd03f28ef349c\"],\"receipt\":null,\"signatures\":["
      "\"ee6b8961c4216274e3d8814d0b56c1c4fbdf7b5b022ae4ce519a825064add3fa88e486ae1e4dc0eeabab7ec5dcb2a837b2babba18dfaf0"
      "11fefac7ef68301e02\","
      "\"fb70831b664533ed049b51ac4db3f0f56a0936dfddf72b6e6bea6a249a3550b7d90e7038b5dff822583079208040bb32dc4c4dd9617945"
      "3969a44f93aecab600\"]},\"nonce\":\"10540996613548414064\"}";

  res_message_t* res = res_message_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_message(ms_res, res) == 0);
  TEST_ASSERT(res->is_error == false);

  core_message_t* msg = res->u.msg;
  TEST_ASSERT_EQUAL_UINT64(9466822412763346725U, msg->network_id);
  TEST_ASSERT_EQUAL_UINT64(10760600709663927622U, msg->nonce);
  TEST_ASSERT_EQUAL_INT(5, core_message_parent_len(msg));

#if 0  // FIXME, parent IDs are in binary form
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
#endif

  milestone_t* ms = (milestone_t*)msg->payload;
  TEST_ASSERT(1613651642 == ms->timestamp);
#if 0  // FIXME, index and signature are in binary form
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
#endif
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

  // validate parent message IDs
  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};
  TEST_ASSERT_EQUAL_INT(4, core_message_parent_len(res->u.msg));
  // compare message ids in binary
  TEST_ASSERT(
      hex_2_bin("0875901a61c4b9f2adb37121fc7946d286dae581d1a5f9cd720cb4c1f8d8f552", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 0), sizeof(tmp_id));
  TEST_ASSERT(
      hex_2_bin("410653be41fde06bdf25aaeb764cd880f872e33e7ce1759801d75964e9dc75c7", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 1), sizeof(tmp_id));
  TEST_ASSERT(
      hex_2_bin("b9130e8d2b928921c220bef325eb9bcad114bdbce80945565e54e8cf9664173a", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 2), sizeof(tmp_id));
  TEST_ASSERT(
      hex_2_bin("cf94502e06fab8dcc4ef9fc94721de2e2fcaf727e0998b6489a0a5b5eead6625", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 3), sizeof(tmp_id));

  // validate payload
  TEST_ASSERT(res->u.msg->payload_type == CORE_MESSAGE_PAYLOAD_TRANSACTION);
  transaction_payload_t* tx = (transaction_payload_t*)res->u.msg->payload;
  // validate essence
  TEST_ASSERT(tx->essence->tx_type == 0);
  // validate essence inputs
  TEST_ASSERT_EQUAL_UINT16(1, utxo_inputs_count(tx->essence->inputs));
  utxo_input_t* inputs = utxo_inputs_find_by_index(tx->essence->inputs, 0);
  TEST_ASSERT(inputs->input_type == 0);
  TEST_ASSERT(inputs->output_index == 0);
  TEST_ASSERT(
      hex_2_bin("0000000000000000000000000000000000000000000000000000000000000000", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, inputs->tx_id, sizeof(tmp_id));
  // validate essence outputs
  TEST_ASSERT_EQUAL_UINT16(2, utxo_outputs_count(tx->essence->outputs));
  // validate output block: 0
  utxo_output_t* outputs = utxo_outputs_get(tx->essence->outputs, 0);
  TEST_ASSERT(outputs->output_type == OUTPUT_EXTENDED);
  output_extended_t* ext_output = (output_extended_t*)outputs->output;
  TEST_ASSERT(ext_output->amount == 10000000);
  TEST_ASSERT_NULL(ext_output->native_tokens);
  TEST_ASSERT_NULL(ext_output->feature_blocks);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions);
  // validate unlock conditions
  TEST_ASSERT(cond_blk_list_len(ext_output->unlock_conditions) == 1);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions->blk);
  // validate address condition block
  unlock_cond_blk_t* cond_block = (unlock_cond_blk_t*)ext_output->unlock_conditions->blk;
  TEST_ASSERT(cond_block->type == UNLOCK_COND_ADDRESS);
  address_t* addr = (address_t*)cond_block->block;
  TEST_ASSERT(addr->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT(
      hex_2_bin("21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, addr->address, sizeof(tmp_id));
  // validate output block: 1
  outputs = utxo_outputs_get(tx->essence->outputs, 1);
  TEST_ASSERT(outputs->output_type == OUTPUT_EXTENDED);
  ext_output = (output_extended_t*)outputs->output;
  TEST_ASSERT(ext_output->amount == 2779530273277761);
  TEST_ASSERT_NULL(ext_output->native_tokens);
  TEST_ASSERT_NULL(ext_output->feature_blocks);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions);
  // validate unlock conditions
  TEST_ASSERT(cond_blk_list_len(ext_output->unlock_conditions) == 1);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions->blk);
  // validate address condition block
  cond_block = (unlock_cond_blk_t*)ext_output->unlock_conditions->blk;
  TEST_ASSERT(cond_block->type == UNLOCK_COND_ADDRESS);
  addr = (address_t*)cond_block->block;
  TEST_ASSERT(addr->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT(
      hex_2_bin("60200bad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe", 65, tmp_id, sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, addr->address, sizeof(tmp_id));

  // TODO: validate essence payload

  // validate transaction unlock blocks
  TEST_ASSERT_EQUAL_UINT16(1, unlock_blocks_count(tx->unlock_blocks));
  unlock_block_t* b = unlock_blocks_get(tx->unlock_blocks, 0);
  TEST_ASSERT_NOT_NULL(b);
  // validate block type
  TEST_ASSERT(b->type == UNLOCK_BLOCK_TYPE_SIGNATURE);
  // validate signature block
  byte_t exp_sig_block[ED25519_SIGNATURE_BLOCK_BYTES];
  // signature block is "00 + public key + signature" in a hex string
  TEST_ASSERT(
      hex_2_bin("0031f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb1b51aab768dd145de99fc3710c7b05963803"
                "f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f810ad0cc4b0210adaafd0a",
                195, exp_sig_block, sizeof(exp_sig_block)) == 0);
  // dump_hex_str(b->block_data, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(exp_sig_block, b->block_data, ED25519_SIGNATURE_BLOCK_BYTES);

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
