// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/get_milestone.h"
#include "core/models/message.h"
#include "core/models/unlock_block.h"
#include "test_config.h"
#include "unity/unity.h"

char const* const test_ms_id = "5d8d0ea61538ca51c95419bcc5958bfd8c791599b66d4f0cdb37c131cde2996a";

void setUp(void) {}

void tearDown(void) {}

void test_deser_get_milestone() {
  char const* const simple_ms =
      "{\"type\": 7,\"index\": 15465,\"timestamp\": 1602227215,\"previousMilestoneId\": "
      "\"0x7ad3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006\",\"parentMessageIds\": "
      "[\"0x7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006\","
      "\"0x7a09324557e9200f39bf493fc8fd6ac43e9ca750c6f6d884cc72386ddcb7d695\","
      "\"0xde9e9d780ba7ebeebc38da16cb53b2a8991d38eee94bcdc3f3ef99aa8c345652\"],\"confirmedMerkleRoot\": "
      "\"0xa18996d96163405e3c0eb13fa3459a07f68a89e8cf7cc239c89e7192344daa5b\",\"appliedMerkleRoot\": "
      "\"0xee26ac07834c603c22130fced361ca58552b0dbfc63e4b73ba24b3b59d9f4050\",\"options\": [{\"type\": "
      "1,\"nextPoWScore\": 2000,\"nextPoWScoreMilestoneIndex\": 15475}],\"metadata\": "
      "\"0xd6ac43e9ca750\",\"signatures\": [{\"type\": 0,\"publicKey\": "
      "\"0xee26ac07834c603c22130fced361ca58552b0dbfc63e4b73ba24b3b59d9f4050\",\"signature\": "
      "\"0x0492a353f96883c472e2686a640e77eda30be8fcc417aa9fc1c15eae854661e0253287be6ea68f649f19ca590de0a6c57fb88635ef0e"
      "013310e0be2b83609503\"}]}";

  res_milestone_t* res = res_milestone_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(deser_get_milestone(simple_ms, res) == 0);
  TEST_ASSERT(res->is_error == false);

  milestone_payload_t* ms = res->u.ms;
  TEST_ASSERT_EQUAL_UINT32(15465, ms->index);
  TEST_ASSERT_EQUAL_UINT32(1602227215, ms->timestamp);

  // check previousMilestoneId
  byte_t tmp_ms_id[IOTA_MESSAGE_ID_BYTES] = {};
  TEST_ASSERT(hex_2_bin("7ad3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006", 65, NULL, tmp_ms_id,
                        sizeof(tmp_ms_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_ms_id, ms->previous_milestone_id, sizeof(tmp_ms_id));

  // check parentMessageIds
  TEST_ASSERT_EQUAL_INT(3, milestone_payload_get_parents_count(ms));
  byte_t tmp_parent_id[IOTA_MESSAGE_ID_BYTES] = {};
  TEST_ASSERT(hex_2_bin("7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006", 65, NULL, tmp_parent_id,
                        sizeof(tmp_parent_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_parent_id, milestone_payload_get_parent(ms, 0), sizeof(tmp_parent_id));
  TEST_ASSERT(hex_2_bin("7a09324557e9200f39bf493fc8fd6ac43e9ca750c6f6d884cc72386ddcb7d695", 65, NULL, tmp_parent_id,
                        sizeof(tmp_parent_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_parent_id, milestone_payload_get_parent(ms, 1), sizeof(tmp_parent_id));
  TEST_ASSERT(hex_2_bin("de9e9d780ba7ebeebc38da16cb53b2a8991d38eee94bcdc3f3ef99aa8c345652", 65, NULL, tmp_parent_id,
                        sizeof(tmp_parent_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_parent_id, milestone_payload_get_parent(ms, 2), sizeof(tmp_parent_id));

  // check appliedMerkleRoot
  TEST_ASSERT(hex_2_bin("a18996d96163405e3c0eb13fa3459a07f68a89e8cf7cc239c89e7192344daa5b", 65, NULL, tmp_ms_id,
                        sizeof(tmp_ms_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_ms_id, ms->confirmed_merkle_root, sizeof(tmp_ms_id));

  // check confirmedMerkleRoot
  TEST_ASSERT(hex_2_bin("ee26ac07834c603c22130fced361ca58552b0dbfc63e4b73ba24b3b59d9f4050", 65, NULL, tmp_ms_id,
                        sizeof(tmp_ms_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_ms_id, ms->applied_merkle_root, sizeof(tmp_ms_id));

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
  TEST_ASSERT_EQUAL_INT(1, milestone_payload_get_signatures_count(ms));
  // signature block is "00 + public key + signature" in a hex string
  TEST_ASSERT(
      hex_2_bin("00ee26ac07834c603c22130fced361ca58552b0dbfc63e4b73ba24b3b59d9f40500492a353f96883c472e2686a640e77eda30b"
                "e8fcc417aa9fc1c15eae854661e0253287be6ea68f649f19ca590de0a6c57fb88635ef0e013310e0be2b83609503",
                194, NULL, tmp_sign, sizeof(tmp_sign)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_sign, milestone_payload_get_signature(ms, 0), sizeof(tmp_sign));

  res_milestone_free(res);
}

void test_get_milestone_by_id() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};
  res_milestone_t* res = res_milestone_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT(get_milestone_by_id(&ctx, test_ms_id, res) == 0);
  if (res->is_error) {
    printf("API error response: %s\n", res->u.error->msg);
  } else {
    milestone_payload_print(res->u.ms, 0);
  }
  res_milestone_free(res);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_get_milestone);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_milestone_by_id);
#endif
  return UNITY_END();
}