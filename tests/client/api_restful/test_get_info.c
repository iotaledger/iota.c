// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/get_node_info.h"
#include "test_config.h"
#include "unity/unity.h"

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
  } else {
    TEST_ASSERT(strlen(info->u.error->msg) > 0);
    printf("Err: %s\n", info->u.error->msg);
  }

  res_node_info_free(info);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"name\":\"HORNET\",\"version\":\"2.0.0-alpha9\",\"status\":{\"isHealthy\":false,\"latestMilestone\":{"
      "\"index\":"
      "4355,\"timestamp\":1651126091,\"milestoneId\":"
      "\"0xcff40dadbd26b5907a4f62e43286709d5b8860f22faf95273c0d1dc483121018\"},\"confirmedMilestone\":{\"index\":4155,"
      "\"timestamp\":1551126091,\"milestoneId\":\"0xfff40dadbd26b5907a4f62e43286709d5b8860f22faf95273c0d1dc483121018\"}"
      ",\"pruningIndex\":290861},\"protocol\":{\"version\":2,\"networkName\":\"alphanet-4\",\"bech32HRP\":\"rms\","
      "\"minPoWScore\":1000,\"rentStructure\":{\"vByteCost\":500,\"vByteFactorData\":1,\"vByteFactorKey\":10},"
      "\"tokenSupply\":\"2779530283277761\"},\"baseToken\":{\"name\":\"Shimmer\",\"tickerSymbol\":\"SMR\",\"unit\":"
      "\"SMR\",\"subunit\":\"glow\",\"decimals\":6,\"useMetricPrefix\":false},\"metrics\":{\"messagesPerSecond\":5.1,"
      "\"referencedMessagesPerSecond\":5.3,\"referencedRate\":86.88524590163934},\"features\":[\"PoW\"],\"plugins\":["
      "\"debug/v1\",\"participation/v1\",\"mqtt/v1\",\"indexer/v1\"]}";

  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = deser_node_info(json_info, info);

  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);
  TEST_ASSERT_EQUAL_STRING("2.0.0-alpha9", info->u.output_node_info->version);
  TEST_ASSERT_FALSE(info->u.output_node_info->is_healthy);

  TEST_ASSERT_EQUAL_UINT32(4355, info->u.output_node_info->latest_milestone.index);
  TEST_ASSERT_EQUAL_UINT32(1651126091, info->u.output_node_info->latest_milestone.timestamp);
  byte_t tmp_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(hex_2_bin("cff40dadbd26b5907a4f62e43286709d5b8860f22faf95273c0d1dc483121018", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, info->u.output_node_info->latest_milestone.milestone_id, sizeof(tmp_id));

  TEST_ASSERT_EQUAL_UINT32(4155, info->u.output_node_info->confirmed_milestone.index);
  TEST_ASSERT_EQUAL_UINT32(1551126091, info->u.output_node_info->confirmed_milestone.timestamp);
  TEST_ASSERT(hex_2_bin("fff40dadbd26b5907a4f62e43286709d5b8860f22faf95273c0d1dc483121018", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, info->u.output_node_info->confirmed_milestone.milestone_id, sizeof(tmp_id));

  TEST_ASSERT_EQUAL_UINT64(290861, info->u.output_node_info->pruning_milestone_index);

  TEST_ASSERT_EQUAL_UINT8(2, info->u.output_node_info->protocol_version);
  TEST_ASSERT_EQUAL_STRING("alphanet-4", info->u.output_node_info->network_name);
  TEST_ASSERT_EQUAL_STRING("rms", info->u.output_node_info->bech32hrp);
  TEST_ASSERT_EQUAL_UINT64(1000, info->u.output_node_info->min_pow_score);

  TEST_ASSERT_EQUAL_UINT16(500, info->u.output_node_info->rent_structure.v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(1, info->u.output_node_info->rent_structure.v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(10, info->u.output_node_info->rent_structure.v_byte_factor_key);

  TEST_ASSERT_EQUAL_STRING("Shimmer", info->u.output_node_info->base_token.name);
  TEST_ASSERT_EQUAL_STRING("SMR", info->u.output_node_info->base_token.ticker_symbol);
  TEST_ASSERT_EQUAL_STRING("SMR", info->u.output_node_info->base_token.unit);
  TEST_ASSERT_EQUAL_STRING("glow", info->u.output_node_info->base_token.subunit);
  TEST_ASSERT_EQUAL_UINT32(6, info->u.output_node_info->base_token.decimals);
  TEST_ASSERT_FALSE(info->u.output_node_info->base_token.use_metric_prefix);

  TEST_ASSERT_EQUAL_FLOAT(5.1, info->u.output_node_info->msg_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(5.3, info->u.output_node_info->referenced_msg_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(86.88524590163934, info->u.output_node_info->referenced_rate);

  TEST_ASSERT_EQUAL_INT(1, get_node_features_num(info));
  TEST_ASSERT_EQUAL_STRING("PoW", get_node_features_at(info, 0));

  TEST_ASSERT_EQUAL_INT(4, get_node_plugins_num(info));
  TEST_ASSERT_EQUAL_STRING("debug/v1", get_node_plugins_at(info, 0));
  TEST_ASSERT_EQUAL_STRING("participation/v1", get_node_plugins_at(info, 1));
  TEST_ASSERT_EQUAL_STRING("mqtt/v1", get_node_plugins_at(info, 2));
  TEST_ASSERT_EQUAL_STRING("indexer/v1", get_node_plugins_at(info, 3));

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