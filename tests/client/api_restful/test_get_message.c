// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>

#include "client/api/restful/get_message.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/payloads/milestone.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "core/models/unlock_block.h"
#include "test_config.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_blk_by_id() {
  char const* const blk_id = "c7217f10fbeabd96afc22cf8b058c4ccc9d2b1fe2b393091b7bda629c3afe222";
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};

  res_block_t* blk = res_block_new();
  TEST_ASSERT_NOT_NULL(blk);
  TEST_ASSERT(get_block_by_id(&ctx, blk_id, blk) == 0);
  if (blk->is_error) {
    printf("API response: %s\n", blk->u.error->msg);
  } else {
    switch (blk->u.blk->payload_type) {
      case CORE_BLOCK_PAYLOAD_TRANSACTION:
        printf("it's a transaction block\n");
        core_block_print(blk->u.blk, 0);
        break;
      case CORE_BLOCK_PAYLOAD_INDEXATION:
        printf("it's an indexation block\n");
        break;
      case CORE_BLOCK_PAYLOAD_MILESTONE:
        printf("it's a milestone block\n");
        core_block_print(blk->u.blk, 0);
        break;
      case CORE_BLOCK_PAYLOAD_RECEIPT:
        printf("it's a receipt block\n");
        break;
      case CORE_BLOCK_PAYLOAD_TREASURY:
        printf("it's a treasury block\n");
        break;
      case CORE_BLOCK_PAYLOAD_TAGGED:
        printf("it's a tagged block\n");
        core_block_print(blk->u.blk, 0);
        break;
      case CORE_BLOCK_PAYLOAD_DEPRECATED_0:
      case CORE_BLOCK_PAYLOAD_DEPRECATED_1:
      case CORE_BLOCK_PAYLOAD_UNKNOWN:
      default:
        printf("unsupported block\n");
        break;
    }
  }
  res_block_free(blk);
}

void test_deser_milestone() {
  char const* const ms_res =
      "{\"protocolVersion\":2,\"parents\":["
      "\"0x596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3\","
      "\"0x8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a\","
      "\"0xa3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893\","
      "\"0xdbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff\"],\"payload\":{\"type\":7,\"index\":3,"
      "\"timestamp\":1644478549,\"protocolVersion\":2,\"previousMilestoneId\":"
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

  res_block_t* res = res_block_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_block(ms_res, res) == 0);
  TEST_ASSERT(res->is_error == false);

  core_block_t* blk = res->u.blk;
  TEST_ASSERT_EQUAL_UINT8(2, blk->protocol_version);
  TEST_ASSERT_EQUAL_UINT64(14757395258967713456u, blk->nonce);

  // check parentMessageIds
  TEST_ASSERT_EQUAL_INT(4, core_block_parent_len(blk));
  byte_t tmp_id[IOTA_BLOCK_ID_BYTES] = {};
  TEST_ASSERT(hex_2_bin("596a369aa0de9c1987b28b945375ac8faa8c420c57d17befc6292be70aaea9f3", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 0), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("8377782f43faa38ef0a223c870137378e9ec2db57b4d68e0bb9bdeb5d1c4bc3a", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 1), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("a3bcf33be3e816c28b295996a31204f64a48aa58adc6f905359e1ffb9ed1b893", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 2), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("dbea0f0641f639a689401e85676214c6b51b0823df4414d3201d33aa7fb34aff", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 3), sizeof(tmp_id));

  TEST_ASSERT(blk->payload_type == CORE_BLOCK_PAYLOAD_MILESTONE);

  milestone_payload_t* ms = (milestone_payload_t*)blk->payload;
  TEST_ASSERT(3 == ms->index);
  TEST_ASSERT(1644478549 == ms->timestamp);
  TEST_ASSERT(2 == ms->protocol_version);

  byte_t tmp_previous_milestone_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(hex_2_bin("b1ddd8775e898f15829ad885f0c2cabdbfc08610adf703019edef6f0c24f5eea", 65, NULL,
                        tmp_previous_milestone_id, sizeof(tmp_previous_milestone_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_previous_milestone_id, ms->previous_milestone_id, sizeof(ms->previous_milestone_id));

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

  // print out a Block object
  core_block_print(res->u.blk, 0);

  res_block_free(res);
}

void test_deser_simple_tx() {
  char const* const simple_tx =
      "{\"protocolVersion\":2,\"parents\":[\"0x224d380a1c6f637864fa46f30c60cb93bf687e80c2d40631d5808fbfae5348a3\","
      "\"0x3ad75671be78f14e58b517bd26871ee347495656a6f7ba4638bac63f4c87b443\","
      "\"0x666952384036118152569a51197af7eaaaccf22760676475602a934fc172e3ed\","
      "\"0xc1e9c2c09169eb8eb862a7cc3836d0472af46eeb57e8f4de1c4c88747fbc3bae\"],\"payload\":{\"type\":6,\"essence\":{"
      "\"type\":1,\"networkId\":\"6983037938332331227\",\"inputs\":[{\"type\":0,\"transactionId\":"
      "\"0x041ce399a476b30d18efefb793e9bc8a8e20e401e13b0ba3ffa8999069e95d25\",\"transactionOutputIndex\":1}],"
      "\"inputsCommitment\":\"0x0dcff67c0531c53863c50bf2242c7187713dc55411df8a1bf12aadf73be1c7e4\",\"outputs\":[{"
      "\"type\":3,\"amount\":\"1000000000\",\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0xbd3a9957b8c5a2959915cb432a467bc2f898ec1ede48dbca033940962a8823fa\"}}]},{\"type\":3,\"amount\":"
      "\"2779502483277761\",\"unlockConditions\":[{\"type\":0,\"address\":{\"type\":0,\"pubKeyHash\":"
      "\"0x3845105b59429361a75b3203a6e24e16d19540aad6bd1936449b62f1c4bbe5da\"}}]}],\"payload\":{\"type\":5,\"tag\":"
      "\"0x484f524e455420464155434554\",\"data\":\"\"}},\"unlocks\":[{\"type\":0,\"signature\":{\"type\":0,"
      "\"publicKey\":\"0x1c51195a9cdc981c3d558707183518a3773bafe6a59857bcba74463e14cb9094\",\"signature\":"
      "\"0x8e04847fa0cfab6737a9ae4460b82370477b8b493a86e1995e9f6cf3898b71cba993bf3110a562e6548b4b8ca83ca671031b2ab3a7bc"
      "f06dd51fef2a884cd90e\"}}]},\"nonce\":\"625872\"}";

  res_block_t* res = res_block_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_block(simple_tx, res) == 0);
  TEST_ASSERT(res->is_error == false);

  // validate protocol version
  TEST_ASSERT_EQUAL_UINT8(2, res->u.blk->protocol_version);

  // validate parent block IDs
  byte_t tmp_id[IOTA_BLOCK_ID_BYTES] = {};
  TEST_ASSERT_EQUAL_INT(4, core_block_parent_len(res->u.blk));
  // compare block ids in binary
  TEST_ASSERT(hex_2_bin("224d380a1c6f637864fa46f30c60cb93bf687e80c2d40631d5808fbfae5348a3", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 0), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("3ad75671be78f14e58b517bd26871ee347495656a6f7ba4638bac63f4c87b443", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 1), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("666952384036118152569a51197af7eaaaccf22760676475602a934fc172e3ed", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 2), sizeof(tmp_id));
  TEST_ASSERT(hex_2_bin("c1e9c2c09169eb8eb862a7cc3836d0472af46eeb57e8f4de1c4c88747fbc3bae", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, core_block_get_parent_id(res->u.blk, 3), sizeof(tmp_id));

  // validate payload
  TEST_ASSERT(res->u.blk->payload_type == CORE_BLOCK_PAYLOAD_TRANSACTION);
  transaction_payload_t* tx = (transaction_payload_t*)res->u.blk->payload;
  // validate essence
  TEST_ASSERT(tx->essence->tx_type == TRANSACTION_ESSENCE_TYPE);
  // validate network ID
  char str_buff[65] = {};
  sprintf(str_buff, "%" PRIu64 "", tx->essence->network_id);
  TEST_ASSERT_EQUAL_STRING("6983037938332331227", str_buff);
  // validate essence inputs
  TEST_ASSERT_EQUAL_UINT16(1, utxo_inputs_count(tx->essence->inputs));
  utxo_input_t* inputs = utxo_inputs_find_by_index(tx->essence->inputs, 1);
  TEST_ASSERT(inputs->input_type == 0);
  TEST_ASSERT(inputs->output_index == 1);
  TEST_ASSERT(hex_2_bin("041ce399a476b30d18efefb793e9bc8a8e20e401e13b0ba3ffa8999069e95d25", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, inputs->tx_id, sizeof(tmp_id));
  // validate essence inputs commitment
  TEST_ASSERT(hex_2_bin("0dcff67c0531c53863c50bf2242c7187713dc55411df8a1bf12aadf73be1c7e4", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, tx->essence->inputs_commitment, sizeof(tmp_id));
  // validate essence outputs
  TEST_ASSERT_EQUAL_UINT16(2, utxo_outputs_count(tx->essence->outputs));
  // validate output: 0
  utxo_output_t* outputs = utxo_outputs_get(tx->essence->outputs, 0);
  TEST_ASSERT(outputs->output_type == OUTPUT_BASIC);
  output_basic_t* ext_output = (output_basic_t*)outputs->output;
  TEST_ASSERT(ext_output->amount == 1000000000);
  TEST_ASSERT_NULL(ext_output->native_tokens);
  TEST_ASSERT_NULL(ext_output->features);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions);
  // validate unlock conditions
  TEST_ASSERT(condition_list_len(ext_output->unlock_conditions) == 1);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions->current);
  // validate address condition block
  unlock_cond_t* cond = (unlock_cond_t*)ext_output->unlock_conditions->current;
  TEST_ASSERT(cond->type == UNLOCK_COND_ADDRESS);
  address_t* addr = (address_t*)cond->obj;
  TEST_ASSERT(addr->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT(hex_2_bin("bd3a9957b8c5a2959915cb432a467bc2f898ec1ede48dbca033940962a8823fa", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, addr->address, sizeof(tmp_id));
  // validate output block: 1
  outputs = utxo_outputs_get(tx->essence->outputs, 1);
  TEST_ASSERT(outputs->output_type == OUTPUT_BASIC);
  ext_output = (output_basic_t*)outputs->output;
  TEST_ASSERT(ext_output->amount == 2779502483277761);
  TEST_ASSERT_NULL(ext_output->native_tokens);
  TEST_ASSERT_NULL(ext_output->features);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions);
  // validate unlock conditions
  TEST_ASSERT(condition_list_len(ext_output->unlock_conditions) == 1);
  TEST_ASSERT_NOT_NULL(ext_output->unlock_conditions->current);
  // validate address condition block
  cond = (unlock_cond_t*)ext_output->unlock_conditions->current;
  TEST_ASSERT(cond->type == UNLOCK_COND_ADDRESS);
  addr = (address_t*)cond->obj;
  TEST_ASSERT(addr->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT(hex_2_bin("3845105b59429361a75b3203a6e24e16d19540aad6bd1936449b62f1c4bbe5da", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, addr->address, sizeof(tmp_id));

  // validate essence payload
  TEST_ASSERT_NOT_NULL(tx->essence->payload);
  // if the essence payload not NULL, it must be a tagged data payload
  tagged_data_payload_t* tag_data = (tagged_data_payload_t*)tx->essence->payload;
  byte_t bin_tag[64] = {};
  TEST_ASSERT(hex_2_bin("484f524e455420464155434554", 27, NULL, bin_tag, sizeof(bin_tag)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(bin_tag, tag_data->tag->data, tag_data->tag->len);
  TEST_ASSERT_NULL(tag_data->data);

  // validate transaction unlock blocks
  TEST_ASSERT_EQUAL_UINT16(1, unlock_list_count(tx->unlocks));
  unlock_t* b = unlock_list_get(tx->unlocks, 0);
  TEST_ASSERT_NOT_NULL(b);
  // validate block type
  TEST_ASSERT(b->type == UNLOCK_SIGNATURE_TYPE);
  // validate signature block
  byte_t exp_sig_block[ED25519_SIGNATURE_BLOCK_BYTES];
  // signature block is "00 + public key + signature" in a hex string
  TEST_ASSERT(
      hex_2_bin("001c51195a9cdc981c3d558707183518a3773bafe6a59857bcba74463e14cb90948e04847fa0cfab6737a9ae4460b82370477b"
                "8b493a86e1995e9f6cf3898b71cba993bf3110a562e6548b4b8ca83ca671031b2ab3a7bcf06dd51fef2a884cd90e",
                195, NULL, exp_sig_block, sizeof(exp_sig_block)) == 0);
  // dump_hex_str(b->block_data, ED25519_SIGNATURE_BLOCK_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(exp_sig_block, b->obj, ED25519_SIGNATURE_BLOCK_BYTES);

  // validate nonce
  sprintf(str_buff, "%" PRIu64 "", res->u.blk->nonce);
  TEST_ASSERT_EQUAL_STRING("625872", str_buff);

  // print a block object
  core_block_print(res->u.blk, 0);

  res_block_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_simple_tx);
  // RUN_TEST(test_deser_milestone);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_blk_by_id);
#endif
  return UNITY_END();
}
