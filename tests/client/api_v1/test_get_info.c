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
  iota_client_conf_t ctx = {.url = TEST_NODE_ENDPOINT, .port = TEST_NODE_PORT};
  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  // test null cases
  TEST_ASSERT_EQUAL_INT(-1, get_node_info(NULL, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_node_info(&ctx, NULL));
  TEST_ASSERT_EQUAL_INT(-1, get_node_info(NULL, info));

  int ret = get_node_info(&ctx, info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);

  res_node_info_free(info);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"data\":{\"name\":\"HORNET\",\"version\":\"0.6.0-alpha\",\"isHealthy\":true,\"networkId\":\"testnet5\","
      "\"bech32HRP\":\"atoi\",\"minPoWScore\":4000,\"latestMilestoneIndex\":22463,\"confirmedMilestoneIndex\":22463,"
      "\"pruningIndex\":0,\"features\":[\"PoW\"]}}";

  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = deser_node_info(json_info, info);

  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);
  TEST_ASSERT_EQUAL_STRING("0.6.0-alpha", info->u.output_node_info->version);
  TEST_ASSERT_TRUE(info->u.output_node_info->is_healthy);
  TEST_ASSERT_EQUAL_STRING("testnet5", info->u.output_node_info->network_id);
  TEST_ASSERT_EQUAL_STRING("atoi", info->u.output_node_info->bech32hrp);
  TEST_ASSERT_EQUAL_UINT64(4000, info->u.output_node_info->min_pow_score);
  TEST_ASSERT_EQUAL_UINT64(22463, info->u.output_node_info->latest_milestone_index);
  TEST_ASSERT_EQUAL_UINT64(22463, info->u.output_node_info->confirmed_milestone_index);
  TEST_ASSERT_EQUAL_UINT64(0, info->u.output_node_info->pruning_milestone_index);

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