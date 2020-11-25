#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unity/unity.h>

#include "client/api/v1/get_balance.h"

#define ADDR "7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006"

void test_get_balance() {
    res_balance_t *res = calloc(1, sizeof(res_balance_t));
    byte_t *addr = "";

    TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, get_balance(NULL, res));
    TEST_ASSERT_EQUAL_INT(-1, get_balance("", NULL));
    TEST_ASSERT_EQUAL_INT(-1, get_balance("", res));
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_get_balance);

  return UNITY_END();
}
