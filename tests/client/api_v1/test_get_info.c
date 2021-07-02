// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "test_config.h"
#include "utarray.h"

#include "client/api/v1/get_node_info.h"

void setUp(void) {}

void tearDown(void) {}

void test_get_info() {
  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};
  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = get_node_info(&ctx, info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  if (info->is_error == false) {
    TEST_ASSERT(strlen(info->u.output_node_info->name) > 0);
    TEST_ASSERT(strlen(info->u.output_node_info->version) > 0);
    TEST_ASSERT(strlen(info->u.output_node_info->bech32hrp) > 0);
    TEST_ASSERT(info->u.output_node_info->min_pow_score > 0);
    TEST_ASSERT(info->u.output_node_info->msg_pre_sec >= 0.0);
    TEST_ASSERT(info->u.output_node_info->referenced_msg_pre_sec >= 0.0);
    TEST_ASSERT(info->u.output_node_info->referenced_rate >= 0.0);
    TEST_ASSERT(info->u.output_node_info->latest_milestone_timestamp > 390326400);
    TEST_ASSERT(info->u.output_node_info->confirmed_milestone_index > 0);
    TEST_ASSERT(info->u.output_node_info->pruning_milestone_index >= 0);
  } else {
    TEST_ASSERT(strlen(info->u.error->msg) > 0);
    printf("Err: %s\n", info->u.error->msg);
  }

  res_node_info_free(info);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"data\":{\"name\":\"HORNET\",\"version\":\"1.0.0-alpha\",\"isHealthy\":true,\"networkId\":\"testnet7\","
      "\"bech32HRP\":\"atoi\",\"minPoWScore\":4000,\"messagesPerSecond\":6.1,\"referencedMessagesPerSecond\":5.3,"
      "\"referencedRate\":86.88524590163934,\"latestMilestoneTimestamp\":1620881772,\"latestMilestoneIndex\":308379,"
      "\"confirmedMilestoneIndex\":308379,\"pruningIndex\":290861,\"features\":[\"PoW\"]}}";

  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = deser_node_info(json_info, info);

  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);
  TEST_ASSERT_EQUAL_STRING("1.0.0-alpha", info->u.output_node_info->version);
  TEST_ASSERT_TRUE(info->u.output_node_info->is_healthy);
  TEST_ASSERT_EQUAL_STRING("testnet7", info->u.output_node_info->network_id);
  TEST_ASSERT_EQUAL_STRING("atoi", info->u.output_node_info->bech32hrp);
  TEST_ASSERT_EQUAL_UINT64(4000, info->u.output_node_info->min_pow_score);
  TEST_ASSERT_EQUAL_UINT64(308379, info->u.output_node_info->latest_milestone_index);
  TEST_ASSERT_EQUAL_UINT64(308379, info->u.output_node_info->confirmed_milestone_index);
  TEST_ASSERT_EQUAL_UINT64(290861, info->u.output_node_info->pruning_milestone_index);
  TEST_ASSERT_EQUAL_FLOAT(6.1, info->u.output_node_info->msg_pre_sec);
  TEST_ASSERT_EQUAL_FLOAT(5.3, info->u.output_node_info->referenced_msg_pre_sec);
  TEST_ASSERT_EQUAL_FLOAT(86.88524590163934, info->u.output_node_info->referenced_rate);
  TEST_ASSERT_EQUAL_UINT64(1620881772, info->u.output_node_info->latest_milestone_timestamp);

  TEST_ASSERT_EQUAL_STRING("PoW", get_node_features_at(info, 0));
  TEST_ASSERT_EQUAL_INT(1, get_node_features_num(info));

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