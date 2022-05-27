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
    TEST_ASSERT(info->u.output_node_info->blk_per_sec >= 0.0);
    TEST_ASSERT(info->u.output_node_info->referenced_blk_per_sec >= 0.0);
    TEST_ASSERT(info->u.output_node_info->referenced_rate >= 0.0);
  } else {
    TEST_ASSERT(strlen(info->u.error->msg) > 0);
    printf("Err: %s\n", info->u.error->msg);
  }

  res_node_info_free(info);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"name\":\"HORNET\",\"version\":\"2.0.0-alpha13\",\"status\":{\"isHealthy\":false,\"latestMilestone\":{"
      "\"index\":11,\"timestamp\":1653486793,\"milestoneId\":"
      "\"0x5e060d6de3857e5b870c2d97db0b3085a035cb7f8377a020e3a16208191c951f\"},\"confirmedMilestone\":{\"index\":11,"
      "\"timestamp\":1653486793,\"milestoneId\":\"0x5e060d6de3857e5b870c2d97db0b3085a035cb7f8377a020e3a16208191c951f\"}"
      ",\"pruningIndex\":0},\"protocol\":{\"version\":2,\"networkName\":\"private_tangle1\",\"bech32HRP\":\"tst\","
      "\"minPoWScore\":1,\"belowMaxDepth\":15,\"rentStructure\":{\"vByteCost\":500,\"vByteFactorData\":1,"
      "\"vByteFactorKey\":10},\"tokenSupply\":\"2779530283277761\"},\"baseToken\":{\"name\":\"TestCoin\","
      "\"tickerSymbol\":\"TEST\",\"unit\":\"TEST\",\"subunit\":\"testies\",\"decimals\":6,\"useMetricPrefix\":false},"
      "\"metrics\":{\"blocksPerSecond\":0.2,\"referencedBlocksPerSecond\":0.2,\"referencedRate\":100},\"features\":["
      "\"PoW\"],\"plugins\":[\"spammer/v1\",\"debug/v1\",\"mqtt/v1\",\"participation/v1\",\"indexer/v1\"]}";

  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = deser_node_info(json_info, info);

  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);
  TEST_ASSERT_EQUAL_STRING("2.0.0-alpha13", info->u.output_node_info->version);
  TEST_ASSERT_FALSE(info->u.output_node_info->is_healthy);

  TEST_ASSERT_EQUAL_UINT32(11, info->u.output_node_info->latest_milestone.index);
  TEST_ASSERT_EQUAL_UINT32(1653486793, info->u.output_node_info->latest_milestone.timestamp);
  byte_t tmp_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(hex_2_bin("5e060d6de3857e5b870c2d97db0b3085a035cb7f8377a020e3a16208191c951f", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, info->u.output_node_info->latest_milestone.milestone_id, sizeof(tmp_id));

  TEST_ASSERT_EQUAL_UINT32(11, info->u.output_node_info->confirmed_milestone.index);
  TEST_ASSERT_EQUAL_UINT32(1653486793, info->u.output_node_info->confirmed_milestone.timestamp);
  TEST_ASSERT(hex_2_bin("5e060d6de3857e5b870c2d97db0b3085a035cb7f8377a020e3a16208191c951f", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, info->u.output_node_info->confirmed_milestone.milestone_id, sizeof(tmp_id));

  TEST_ASSERT_EQUAL_UINT64(0, info->u.output_node_info->pruning_milestone_index);

  TEST_ASSERT_EQUAL_UINT8(2, info->u.output_node_info->protocol_version);
  TEST_ASSERT_EQUAL_STRING("private_tangle1", info->u.output_node_info->network_name);
  TEST_ASSERT_EQUAL_STRING("tst", info->u.output_node_info->bech32hrp);
  TEST_ASSERT_EQUAL_UINT64(1, info->u.output_node_info->min_pow_score);

  TEST_ASSERT_EQUAL_UINT16(500, info->u.output_node_info->rent_structure.v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(1, info->u.output_node_info->rent_structure.v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(10, info->u.output_node_info->rent_structure.v_byte_factor_key);

  TEST_ASSERT_EQUAL_STRING("TestCoin", info->u.output_node_info->base_token.name);
  TEST_ASSERT_EQUAL_STRING("TEST", info->u.output_node_info->base_token.ticker_symbol);
  TEST_ASSERT_EQUAL_STRING("TEST", info->u.output_node_info->base_token.unit);
  TEST_ASSERT_EQUAL_STRING("testies", info->u.output_node_info->base_token.subunit);
  TEST_ASSERT_EQUAL_UINT32(6, info->u.output_node_info->base_token.decimals);
  TEST_ASSERT_FALSE(info->u.output_node_info->base_token.use_metric_prefix);

  TEST_ASSERT_EQUAL_FLOAT(0.2, info->u.output_node_info->blk_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(0.2, info->u.output_node_info->referenced_blk_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(100, info->u.output_node_info->referenced_rate);

  TEST_ASSERT_EQUAL_INT(1, get_node_features_num(info));
  TEST_ASSERT_EQUAL_STRING("PoW", get_node_features_at(info, 0));

  TEST_ASSERT_EQUAL_INT(5, get_node_plugins_num(info));
  TEST_ASSERT_EQUAL_STRING("spammer/v1", get_node_plugins_at(info, 0));
  TEST_ASSERT_EQUAL_STRING("debug/v1", get_node_plugins_at(info, 1));
  TEST_ASSERT_EQUAL_STRING("mqtt/v1", get_node_plugins_at(info, 2));
  TEST_ASSERT_EQUAL_STRING("participation/v1", get_node_plugins_at(info, 3));
  TEST_ASSERT_EQUAL_STRING("indexer/v1", get_node_plugins_at(info, 4));

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
