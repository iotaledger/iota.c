#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_node_info.h"

void test_get_info() {
  iota_client_conf_t ctx = {
      .url = "https://iota-node/",
      .port = 14265  // use default port number
  };
  res_node_info_t info;

  int ret = get_node_info(&ctx, &info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_EQUAL_STRING("HORNET", info.name);
  TEST_ASSERT_EQUAL_STRING("0.5.3", info.version);
}

void test_deser_node_info() {
  char const* const json_info =
      "{\"data\":{\"name\":\"HORNET\",\"version\":\"0.5.3\",\"isHealthy\":true,\"networkId\":234,\"latestMilestoneId\":"
      "\"1a4a9199997db6ec0d6c798040e057df2b505616e5e887257b0600eee49f6345\",\"latestMilestoneIndex\":82847,"
      "\"solidMilestoneId\":\"1a4a9199997db6ec0d6c798040e057df2b505616e5e887257b0600eee49f6345\","
      "\"solidMilestoneIndex\":82847,\"pruningIndex\":82325,\"features\":[]}}}}";

  res_node_info_t info = {};
  int ret = deser_node_info(json_info, &info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_EQUAL_STRING("HORNET", info.name);
  TEST_ASSERT_EQUAL_STRING("0.5.3", info.version);
  // TODO
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_node_info);
  // RUN_TEST(test_get_info);

  return UNITY_END();
}