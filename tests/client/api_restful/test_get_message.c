// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>

#include "client/api/restful/get_message.h"
#include "core/models/payloads/milestone.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "test_config.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_msg_by_id() {
  char const* const msg_id = "c7217f10fbeabd96afc22cf8b058c4ccc9d2b1fe2b393091b7bda629c3afe222";
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
        core_message_print(msg->u.msg, 0);
        break;
      case CORE_MESSAGE_PAYLOAD_INDEXATION:
        printf("it's an indexation message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_MILESTONE:
        printf("it's a milestone message\n");
        core_message_print(msg->u.msg, 0);
        break;
      case CORE_MESSAGE_PAYLOAD_RECEIPT:
        printf("it's a receipt message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_TREASURY:
        printf("it's a treasury message\n");
        break;
      case CORE_MESSAGE_PAYLOAD_TAGGED:
        printf("it's a tagged message\n");
        core_message_print(msg->u.msg, 0);
        break;
      case CORE_MESSAGE_PAYLOAD_DEPRECATED_0:
      case CORE_MESSAGE_PAYLOAD_DEPRECATED_1:
      case CORE_MESSAGE_PAYLOAD_UNKNOWN:
      default:
        printf("unsupported message\n");
        break;
    }
  }
  res_message_free(msg);
}

void test_deser_milestone() {
  char const* const ms_res =
      "{\"protocolVersion\":2,\"parentMessageIds\":["
      "\"0x596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3\","
      "\"0x8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a\","
      "\"0xa3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893\","
      "\"0xdbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff\"],\"payload\":{\"type\":7,\"index\":3,"
      "\"timestamp\":1644478549,\"lastMilestoneId\":"
      "\"0xb1ddd8775e898f15829ad885f0c2cabdbfc08610adf703019edef6f0c24f5eea\",\"parentMessageIds\":["
      "\"0x596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3\","
      "\"0x8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a\","
      "\"0xa3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893\","
      "\"0xdbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff\"],\"confirmedMerkleRoot\":"
      "\"0x58f3fe3e0727eb7a34a2fe8a7a3d2a1b5b33650c26b34c1955909db3e8a1176c\",\"appliedMerkleRoot\":"
      "\"0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8\",\"metadata\":"
      "\"0x96a31204f64a48aa58adc6ff90\",\"options\":[{\"type\":0},{\"type\":1,\"nextPoWScore\":2000,"
      "\"nextPoWScoreMilestoneIndex\":15475}],\"signatures\":[{\"type\":0,\"publicKey\":"
      "\"0xd85e5b1590d898d1e0cdebb2e3b5337c8b76270142663d78811683ba47c17c98\",\"signature\":"
      "\"0x51306b228a716b656000529b72520fc97cf227197056b289d94d717779cb9749fe9cde77477497cfc594a728ce372b8a7edf233115fb"
      "51681e4669f6f4464900\"},{\"type\":0,\"publicKey\":"
      "\"0xd9922819a39e94ddf3907f4b9c8df93f39f026244fcb609205b9a879022599f2\",\"signature\": "
      "\"0x1e5fff5396cfa5e9b247ab6cb402c9dfd9b239e6bcaa3c9e370789f3e180599ea267c4b4e61be4864cfae61261af5353b45c2277e1eb"
      "3f8bb178211ea7e3e003\"},{\"type\":0,\"publicKey\":"
      "\"0xf9d9656a60049083eef61487632187b351294c1fa23d118060d813db6d03e8b6\",\"signature\": "
      "\"0xb5be8a9e682df9a900dc0961150d24b6b13418ce11744530b688de852525d939026c9ebb2af66aebecbbe06287149677a7a2e92e9f7f"
      "9182ee9fb0681d3e8d0c\"}]},\"nonce\":\"14757395258967713456\"}";

  res_message_t* res = res_message_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_message(ms_res, res) == 0);
  TEST_ASSERT(res->is_error == false);

  core_message_t* msg = res->u.msg;
  TEST_ASSERT_EQUAL_UINT8(2, msg->protocol_version);
  TEST_ASSERT_EQUAL_UINT64(14757395258967713456u, msg->nonce);

  // check parentMessageIds
  TEST_ASSERT_EQUAL_INT(4, core_message_parent_len(msg));
  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};
  TEST_ASSERT(hex_2_bin("596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 0), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 1), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("a3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 2), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("dbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 3), sizeof(tmp_id));

  TEST_ASSERT(msg->payload_type == CORE_MESSAGE_PAYLOAD_MILESTONE);

  milestone_payload_t* ms = (milestone_payload_t*)msg->payload;
  TEST_ASSERT(3 == ms->index);
  TEST_ASSERT(1644478549 == ms->timestamp);

  byte_t tmp_last_milestone_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(hex_2_bin("b1ddd8775e898f15829ad885f0c2cabdbfc08610adf703019edef6f0c24f5eea", 65, NULL,
                        tmp_last_milestone_id, sizeof(tmp_last_milestone_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_last_milestone_id, ms->last_milestone_id, sizeof(ms->last_milestone_id));

  // check parentMessageIds
  TEST_ASSERT_EQUAL_INT(4, milestone_payload_get_parents_count(ms));
  TEST_ASSERT(hex_2_bin("596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, milestone_payload_get_parent(ms, 0), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, milestone_payload_get_parent(ms, 1), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("a3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, milestone_payload_get_parent(ms, 2), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("dbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, milestone_payload_get_parent(ms, 3), sizeof(tmp_id));

  byte_t tmp_proof[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(hex_2_bin("58f3fe3e0727eb7a34a2fe8a7a3d2a1b5b33650c26b34c1955909db3e8a1176c", 65, NULL, tmp_proof,
                        sizeof(tmp_proof)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_proof, ms->confirmed_merkle_root, sizeof(ms->confirmed_merkle_root));

  TEST_ASSERT(hex_2_bin("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", 65, NULL, tmp_proof,
                        sizeof(tmp_proof)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_proof, ms->applied_merkle_root, sizeof(ms->applied_merkle_root));

  // check metadata
  byte_t tmp_metadata[13] = {};
  TEST_ASSERT(hex_2_bin("96a31204f64a48aa58adc6ff90", 26, NULL, tmp_metadata, sizeof(tmp_metadata)) == 0);
  TEST_ASSERT_EQUAL_UINT32(13, ms->metadata->len);
  TEST_ASSERT_EQUAL_MEMORY(tmp_metadata, ms->metadata->data, sizeof(tmp_metadata));

  // check options
  TEST_ASSERT_NOT_NULL(ms->options);
  TEST_ASSERT_NOT_NULL(ms->options->option);
  TEST_ASSERT_EQUAL_UINT8(MILESTONE_OPTION_POW, ms->options->option->type);
  TEST_ASSERT_NOT_NULL(ms->options->option->option);
  TEST_ASSERT_EQUAL_UINT32(2000, ((milestone_pow_option_t*)ms->options->option->option)->next_pow_score);
  TEST_ASSERT_EQUAL_UINT32(15475,
                           ((milestone_pow_option_t*)ms->options->option->option)->next_pow_score_milestone_index);

  // check signatures
  byte_t tmp_sign[ED25519_SIGNATURE_BLOCK_BYTES] = {};
  TEST_ASSERT_EQUAL_INT(3, milestone_payload_get_signatures_count(ms));
  TEST_ASSERT(
      hex_2_bin("00d85e5b1590d898d1e0cdebb2e3b5337c8b76270142663d78811683ba47c17c9851306b228a716b656000529b72520fc97cf2"
                "27197056b289d94d717779cb9749fe9cde77477497cfc594a728ce372b8a7edf233115fb51681e4669f6f4464900",
                194, NULL, tmp_sign, sizeof(tmp_sign)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_sign, milestone_payload_get_signature(ms, 0), sizeof(tmp_sign));
  TEST_ASSERT(
      hex_2_bin("00d9922819a39e94ddf3907f4b9c8df93f39f026244fcb609205b9a879022599f21e5fff5396cfa5e9b247ab6cb402c9dfd9b2"
                "39e6bcaa3c9e370789f3e180599ea267c4b4e61be4864cfae61261af5353b45c2277e1eb3f8bb178211ea7e3e003",
                194, NULL, tmp_sign, sizeof(tmp_sign)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_sign, milestone_payload_get_signature(ms, 1), sizeof(tmp_sign));
  TEST_ASSERT(
      hex_2_bin("00f9d9656a60049083eef61487632187b351294c1fa23d118060d813db6d03e8b6b5be8a9e682df9a900dc0961150d24b6b134"
                "18ce11744530b688de852525d939026c9ebb2af66aebecbbe06287149677a7a2e92e9f7f9182ee9fb0681d3e8d0c",
                194, NULL, tmp_sign, sizeof(tmp_sign)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_sign, milestone_payload_get_signature(ms, 2), sizeof(tmp_sign));

  // print core message
  core_message_print(res->u.msg, 0);

  res_message_free(res);
}

void test_deser_simple_tx() {
  char const* const simple_tx =
      "{\"protocolVersion\":2,\"parentMessageIds\":["
      "\"0x0875901a61c4b9f2adb37121fc7946d286dae581d1a5f9cd720cb4c1f8d8f552\","
      "\"0x410653be41fde06bdf25aaeb764cd880f872e33e7ce1759801d75964e9dc75c7\","
      "\"0xb9130e8d2b928921c220bef325eb9bcad114bdbce80945565e54e8cf9664173a\","
      "\"0xcf94502e06fab8dcc4ef9fc94721de2e2fcaf727e0998b6489a0a5b5eead6625\"],\"payload\":{\"type\":6,\"essence\":{"
      "\"type\":1,\"networkId\":\"8453507715857476362\",\"inputs\":[{\"type\":0,\"transactionId\":"
      "\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"transactionOutputIndex\":0}],"
      "\"inputsCommitment\":\"0x9f0a1533b91ad7551645dd07d1c21833fff81e74af492af0ca6d99ab7f63b5c9\",\"outputs\":"
      "[{\"type\":3,\"amount\":\"10000000\",\"nativeTokens\":[],\"unlockConditions\":[{\"type\":0,\"address\":{"
      "\"type\":0,\"pubKeyHash\":\"0x21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942\"}}],"
      "\"featureBlocks\":[]},{\"type\":3,\"amount\":\"2779530273277761\",\"nativeTokens\":[],\"unlockConditions\":[{"
      "\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x60200bad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe\"}}],\"featureBlocks\":[]}],\"payload\":{"
      "\"type\":5,\"tag\":\"0x484f524e455420464155434554\",\"data\":\"0x\"}},\"unlockBlocks\":[{\"type\":0,"
      "\"signature\":{\"type\":0,\"publicKey\":\"0x31f176dadf38cdec0eadd1d571394be78f0bbee3ed594316678dffc162a095cb\","
      "\"signature\":"
      "\"0x1b51aab768dd145de99fc3710c7b05963803f28c0a93532341385ad52cbeb879142cc708cb3a44269e0e27785fb3e160efc9fe034f81"
      "0ad0cc4b0210adaafd0a\"}}]},\"nonce\":\"62900\"}";

  res_message_t* res = res_message_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_message(simple_tx, res) == 0);
  TEST_ASSERT(res->is_error == false);

  // validate protocol version
  TEST_ASSERT_EQUAL_UINT8(2, res->u.msg->protocol_version);

  // validate parent message IDs
  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};
  TEST_ASSERT_EQUAL_INT(4, core_message_parent_len(res->u.msg));
  // compare message ids in binary
  TEST_ASSERT(hex_2_bin("0875901a61c4b9f2adb37121fc7946d286dae581d1a5f9cd720cb4c1f8d8f552", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 0), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("410653be41fde06bdf25aaeb764cd880f872e33e7ce1759801d75964e9dc75c7", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 1), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("b9130e8d2b928921c220bef325eb9bcad114bdbce80945565e54e8cf9664173a", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 2), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("cf94502e06fab8dcc4ef9fc94721de2e2fcaf727e0998b6489a0a5b5eead6625", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_message_get_parent_id(res->u.msg, 3), sizeof(tmp_id));

  // validate payload
  TEST_ASSERT(res->u.msg->payload_type == CORE_MESSAGE_PAYLOAD_TRANSACTION);
  transaction_payload_t* tx = (transaction_payload_t*)res->u.msg->payload;
  // validate essence
  TEST_ASSERT(tx->essence->tx_type == TRANSACTION_ESSENCE_TYPE);
  // validate network ID
  char str_buff[65] = {};
  sprintf(str_buff, "%" PRIu64 "", tx->essence->network_id);
  TEST_ASSERT_EQUAL_STRING("8453507715857476362", str_buff);
  // validate essence inputs
  TEST_ASSERT_EQUAL_UINT16(1, utxo_inputs_count(tx->essence->inputs));
  utxo_input_t* inputs = utxo_inputs_find_by_index(tx->essence->inputs, 0);
  TEST_ASSERT(inputs->input_type == 0);
  TEST_ASSERT(inputs->output_index == 0);
  TEST_ASSERT(hex_2_bin("0000000000000000000000000000000000000000000000000000000000000000", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, inputs->tx_id, sizeof(tmp_id));
  // validate essence inputs commitment
  TEST_ASSERT(hex_2_bin("9f0a1533b91ad7551645dd07d1c21833fff81e74af492af0ca6d99ab7f63b5c9", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, tx->essence->inputs_commitment, sizeof(tmp_id));
  // validate essence outputs
  TEST_ASSERT_EQUAL_UINT16(2, utxo_outputs_count(tx->essence->outputs));
  // validate output block: 0
  utxo_output_t* outputs = utxo_outputs_get(tx->essence->outputs, 0);
  TEST_ASSERT(outputs->output_type == OUTPUT_BASIC);
  output_basic_t* ext_output = (output_basic_t*)outputs->output;
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
  TEST_ASSERT(hex_2_bin("21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, addr->address, sizeof(tmp_id));
  // validate output block: 1
  outputs = utxo_outputs_get(tx->essence->outputs, 1);
  TEST_ASSERT(outputs->output_type == OUTPUT_BASIC);
  ext_output = (output_basic_t*)outputs->output;
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
  TEST_ASSERT(hex_2_bin("60200bad8137a704216e84f8f9acfe65b972d9f4155becb4815282b03cef99fe", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
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
                195, NULL, exp_sig_block, sizeof(exp_sig_block)) == 0);
  // dump_hex_str(b->block_data, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(exp_sig_block, b->block_data, ED25519_SIGNATURE_BLOCK_BYTES);

  // validate nonce
  sprintf(str_buff, "%" PRIu64 "", res->u.msg->nonce);
  TEST_ASSERT_EQUAL_STRING("62900", str_buff);

  // print core message
  core_message_print(res->u.msg, 0);

  res_message_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_simple_tx);
  RUN_TEST(test_deser_milestone);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_msg_by_id);
#endif
  return UNITY_END();
}
