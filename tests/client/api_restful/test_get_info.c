// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"
#include "utarray.h"

#include "client/api/restful/get_node_info.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_info() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};
  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = get_node_info(&ctx, info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  if (info->is_error == false) {
    node_info_print(info, 1);
    TEST_ASSERT(strlen(info->u.output_node_info->name) > 0);
    TEST_ASSERT(strlen(info->u.output_node_info->version) > 0);
    TEST_ASSERT(strlen(info->u.output_node_info->bech32hrp) > 0);
    TEST_ASSERT(info->u.output_node_info->min_pow_score > 0);
    TEST_ASSERT(info->u.output_node_info->msg_per_sec >= 0.0);
    TEST_ASSERT(info->u.output_node_info->referenced_msg_per_sec >= 0.0);
    TEST_ASSERT(info->u.output_node_info->referenced_rate >= 0.0);
    TEST_ASSERT(info->u.output_node_info->latest_milestone_timestamp > 390326400);
    TEST_ASSERT(info->u.output_node_info->confirmed_milestone_index > 0);
    TEST_ASSERT(info->u.output_node_info->pruning_milestone_index > 0);
  } else {
    TEST_ASSERT(strlen(info->u.error->msg) > 0);
    printf("Err: %s\n", info->u.error->msg);
  }

  res_node_info_free(info);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"name\":\"HORNET\",\"version\":\"2.0.0-alpha1\",\"status\":{\"isHealthy\":false,\"latestMilestoneTimestamp\":"
      "1644469172,\"latestMilestoneIndex\":6,\"confirmedMilestoneIndex\":308379,\"pruningIndex\":290861},\"metrics\":{"
      "\"messagesPerSecond\":5.1,\"referencedMessagesPerSecond\":5.3,\"referencedRate\":86.88524590163934},"
      "\"protocol\":{"
      "\"networkName\":\"private_tangle1\",\"protocolVersion\":2,\"bech32HRP\":\"atoi\",\"minPoWScore\":100,"
      "\"rentStructure\":{\"vByteCost\":"
      "0,\"vByteFactorData\":1,\"vByteFactorKey\":10}},\"features\":[\"PoW\"],\"plugins\":[\"spammer/v1\",\"debug/"
      "v1\",\"faucet/v1\",\"indexer/v1\"]}";

  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = deser_node_info(json_info, info);

  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);
  TEST_ASSERT_EQUAL_STRING("2.0.0-alpha1", info->u.output_node_info->version);
  TEST_ASSERT_FALSE(info->u.output_node_info->is_healthy);
  TEST_ASSERT_EQUAL_STRING("private_tangle1", info->u.output_node_info->network_name);
  TEST_ASSERT_EQUAL_STRING("atoi", info->u.output_node_info->bech32hrp);
  TEST_ASSERT_EQUAL_UINT64(100, info->u.output_node_info->min_pow_score);
  TEST_ASSERT_EQUAL_UINT64(6, info->u.output_node_info->latest_milestone_index);
  TEST_ASSERT_EQUAL_UINT64(308379, info->u.output_node_info->confirmed_milestone_index);
  TEST_ASSERT_EQUAL_UINT64(290861, info->u.output_node_info->pruning_milestone_index);
  TEST_ASSERT_EQUAL_FLOAT(5.1, info->u.output_node_info->msg_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(5.3, info->u.output_node_info->referenced_msg_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(86.88524590163934, info->u.output_node_info->referenced_rate);
  TEST_ASSERT_EQUAL_UINT64(1644469172, info->u.output_node_info->latest_milestone_timestamp);

  TEST_ASSERT_EQUAL_UINT16(0, info->u.output_node_info->v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(1, info->u.output_node_info->v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(10, info->u.output_node_info->v_byte_factor_key);

  TEST_ASSERT_EQUAL_STRING("PoW", get_node_features_at(info, 0));
  TEST_ASSERT_EQUAL_INT(1, get_node_features_num(info));

  TEST_ASSERT_EQUAL_STRING("spammer/v1", get_node_plugins_at(info, 0));
  TEST_ASSERT_EQUAL_STRING("debug/v1", get_node_plugins_at(info, 1));
  TEST_ASSERT_EQUAL_STRING("faucet/v1", get_node_plugins_at(info, 2));
  TEST_ASSERT_EQUAL_STRING("indexer/v1", get_node_plugins_at(info, 3));
  TEST_ASSERT_EQUAL_INT(4, get_node_plugins_num(info));

  res_node_info_free(info);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_node_info);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_info);
#endif
  return UNITY_END();
}