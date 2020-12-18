#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_node_info.h"

void test_get_info() {
  iota_client_conf_t ctx = {
      .url = "https://iota-node/",
      .port = 14265  // use default port number
  };
  res_node_info_t* info = res_node_info_new();

  int ret = get_node_info(&ctx, info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);
  // TEST_ASSERT_EQUAL_STRING("0.6.0-alpha", info->u.output_node_info->version);
  // TEST_ASSERT_EQUAL_STRING("alphanet1", info->u.output_node_info->network_id);

  res_node_info_free(info);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"data\":{\"name\":\"HORNET\",\"version\":\"0.6.0-alpha\",\"isHealthy\":true,\"networkId\":\"alphanet1\","
      "\"latestMilestoneId\":"
      "\"1a4a9199997db6ec0d6c798040e057df2b505616e5e887257b0600eee49f6345\",\"latestMilestoneIndex\":82847,"
      "\"solidMilestoneId\":\"1a4a9199997db6ec0d6c798040e057df2b505616e5e887257b0600eee49f6345\","
      "\"solidMilestoneIndex\":82847,\"pruningIndex\":82325,\"features\":[]}}}}";

  res_node_info_t* info = res_node_info_new();
  int ret = deser_node_info(json_info, info);

  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_EQUAL_STRING("HORNET", info->u.output_node_info->name);
  TEST_ASSERT_EQUAL_STRING("0.6.0-alpha", info->u.output_node_info->version);
  TEST_ASSERT_TRUE(info->u.output_node_info->is_healthy);
  TEST_ASSERT_EQUAL_STRING("alphanet1", info->u.output_node_info->network_id);

  res_node_info_free(info);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_node_info);
  // RUN_TEST(test_get_info);

  return UNITY_END();
}