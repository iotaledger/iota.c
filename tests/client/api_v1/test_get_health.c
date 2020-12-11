#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_health.h"

void test_get_health() {
  iota_client_conf_t ctx = {
      .url = "http://localhost/",
      .port = 0  // use default port number
  };
  bool health = false;
  TEST_ASSERT(get_health(&ctx, &health) == 0);
}

int main() {
  UNITY_BEGIN();

  // RUN_TEST(test_get_health);

  return UNITY_END();
}