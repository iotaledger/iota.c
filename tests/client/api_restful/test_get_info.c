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
    TEST_ASSERT(strlen(info->u.info->name) > 0);
    TEST_ASSERT(strlen(info->u.info->version) > 0);
    TEST_ASSERT(strlen(info->u.info->protocol_params.bech32hrp) > 0);
    TEST_ASSERT(info->u.info->protocol_params.min_pow_score > 0);
    TEST_ASSERT(info->u.info->metrics.block_per_sec >= 0.0);
    TEST_ASSERT(info->u.info->metrics.referenced_block_per_sec >= 0.0);
    TEST_ASSERT(info->u.info->metrics.referenced_rate >= 0.0);
  } else {
    TEST_ASSERT(strlen(info->u.error->msg) > 0);
    printf("Err: %s\n", info->u.error->msg);
  }

  res_node_info_free(info);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"name\":\"HORNET\",\"version\":\"2.0.0-alpha.23\",\"status\":{\"isHealthy\":true,\"latestMilestone\":{"
      "\"index\":969,\"timestamp\":1657273891,\"milestoneId\":"
      "\"0x24db3136e62253e6123d16aeca1d44d0e6c861a1d4a82ec2476a9b7fb6530efa\"},\"confirmedMilestone\":{\"index\":969,"
      "\"timestamp\":1657273891,\"milestoneId\":\"0x24db3136e62253e6123d16aeca1d44d0e6c861a1d4a82ec2476a9b7fb6530efa\"}"
      ",\"pruningIndex\":0},\"supportedProtocolVersions\":[2],\"protocol\":{\"version\":2,\"networkName\":\"alphanet-"
      "8\",\"bech32HRP\":\"rms\",\"minPoWScore\":1000,\"belowMaxDepth\":15,\"rentStructure\":{\"vByteCost\":500,"
      "\"vByteFactorData\":1,\"vByteFactorKey\":10},\"tokenSupply\":\"2779530283277761\"},"
      "\"pendingProtocolParameters\":[],\"baseToken\":{\"name\":\"Shimmer\",\"tickerSymbol\":\"SMR\",\"unit\":\"SMR\","
      "\"subunit\":\"glow\",\"decimals\":6,\"useMetricPrefix\":false},\"metrics\":{\"blocksPerSecond\":1.4,"
      "\"referencedBlocksPerSecond\":1.4,\"referencedRate\":100},\"features\":[\"PoW\"]}";

  res_node_info_t* info = res_node_info_new();
  TEST_ASSERT_NOT_NULL(info);

  int ret = deser_node_info(json_info, info);

  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(info->is_error);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.info->name);
  TEST_ASSERT_EQUAL_STRING("2.0.0-alpha.23", info->u.info->version);
  TEST_ASSERT_TRUE(info->u.info->status.is_healthy);

  TEST_ASSERT_EQUAL_UINT32(969, info->u.info->status.latest_milestone.index);
  TEST_ASSERT_EQUAL_UINT32(1657273891, info->u.info->status.latest_milestone.timestamp);
  byte_t tmp_id[CRYPTO_BLAKE2B_256_HASH_BYTES] = {};
  TEST_ASSERT(hex_2_bin("24db3136e62253e6123d16aeca1d44d0e6c861a1d4a82ec2476a9b7fb6530efa", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, info->u.info->status.latest_milestone.milestone_id, sizeof(tmp_id));

  TEST_ASSERT_EQUAL_UINT32(969, info->u.info->status.confirmed_milestone.index);
  TEST_ASSERT_EQUAL_UINT32(1657273891, info->u.info->status.confirmed_milestone.timestamp);
  TEST_ASSERT(hex_2_bin("24db3136e62253e6123d16aeca1d44d0e6c861a1d4a82ec2476a9b7fb6530efa", 65, NULL, tmp_id,
                        sizeof(tmp_id)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(tmp_id, info->u.info->status.confirmed_milestone.milestone_id, sizeof(tmp_id));

  TEST_ASSERT_EQUAL_UINT64(0, info->u.info->status.pruning_index);

  TEST_ASSERT_EQUAL_UINT8(2, info->u.info->protocol_params.version);
  TEST_ASSERT_EQUAL_STRING("alphanet-8", info->u.info->protocol_params.network_name);
  TEST_ASSERT_EQUAL_STRING("rms", info->u.info->protocol_params.bech32hrp);
  TEST_ASSERT_EQUAL_UINT32(1000, info->u.info->protocol_params.min_pow_score);
  TEST_ASSERT_EQUAL_UINT8(15, info->u.info->protocol_params.below_max_deep);
  TEST_ASSERT_EQUAL_UINT64(2779530283277761, info->u.info->protocol_params.token_supply);

  TEST_ASSERT_EQUAL_UINT16(500, info->u.info->protocol_params.rent.v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(1, info->u.info->protocol_params.rent.v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(10, info->u.info->protocol_params.rent.v_byte_factor_key);

  TEST_ASSERT_EQUAL_STRING("Shimmer", info->u.info->base_token.name);
  TEST_ASSERT_EQUAL_STRING("SMR", info->u.info->base_token.ticker_symbol);
  TEST_ASSERT_EQUAL_STRING("SMR", info->u.info->base_token.unit);
  TEST_ASSERT_EQUAL_STRING("glow", info->u.info->base_token.subunit);
  TEST_ASSERT_EQUAL_UINT32(6, info->u.info->base_token.decimals);
  TEST_ASSERT_FALSE(info->u.info->base_token.use_metric_prefix);

  TEST_ASSERT_EQUAL_FLOAT(1.4, info->u.info->metrics.block_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(1.4, info->u.info->metrics.referenced_block_per_sec);
  TEST_ASSERT_EQUAL_FLOAT(100, info->u.info->metrics.referenced_rate);

  TEST_ASSERT_EQUAL_INT(1, get_node_features_num(info));
  TEST_ASSERT_EQUAL_STRING("PoW", get_node_features_at(info, 0));

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
