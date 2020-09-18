#include <stdio.h>
#include <unity/unity.h>

#include "client/api/get_node_info.h"

void test_get_info() {
  iota_client_conf_t ctx = {
      .url = "https://virtserver.swaggerhub.com/oopsmonk/mytest/0.0.1/",
      .port = 0  // use default port number
  };
  res_node_info_t info;

  int ret = get_node_info(&ctx, &info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_EQUAL_STRING("Hornet", info.name);
  TEST_ASSERT_EQUAL_STRING("0.5.2", info.version);
}

void test_deser_node_info() {
  char const* const json_info =
      "{ \"data\": { \"name\": \"Hornet\", \"version\": \"0.5.2\", \"isHealthy\": true, \"operatingNetwork\": "
      "\"Mainnet\", \"peers\": 5, \"coordinatorAddress\": "
      "\"UDYXTZBE9GZGPM9SSQV9LTZNDLJIZMPUVVXYXFYVBLIEUHLSEWFTKZZLXYRHHWVQV9MNNX9KZC9D9UZWZ\", \"isSynced\": true, "
      "\"latestMilestoneHash\": \"JXVC9LGIEPCEJLEN9EXOKGUBFXOZDTZYIMZMPIJCGUALBENVTTRFYVUCKZCOVPRZKEUYZGYPSQGAA9999\", "
      "\"latestMilestoneIndex\": 1699556, \"latestSolidMilestoneHash\": "
      "\"JXVC9LGIEPCEJLEN9EXOKGUBFXOZDTZYIMZMPIJCGUALBENVTTRFYVUCKZCOVPRZKEUYZGYPSQGAA9999\", "
      "\"latestSolidMilestoneIndex\": 1699556, \"pruningIndex\": 1696326, \"time\": 1599584382, \"features\": [ "
      "\"Plugin X\", \"Plugin Y\" ] } }";

  res_node_info_t info = {};
  int ret = deser_node_info(json_info, &info);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_EQUAL_STRING("Hornet", info.name);
  TEST_ASSERT_EQUAL_STRING("0.5.2", info.version);
  // TODO
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_node_info);
  RUN_TEST(test_get_info);

  return UNITY_END();
}