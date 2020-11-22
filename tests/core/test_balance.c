#include <stdio.h>

#include "core/balance.h"
#include "unity/unity.h"

void test_balance() {
  balance_t balan;
  byte_t balance_byte[sizeof(balance_t)];
  // Note: colored coins are not yet included to Chrysalis, only Pollen
  // byte_t color[BALANCE_COLOR_BYTES];
  balance_t balan_exp;

  // create a new balance
  // Note: colored coins are not yet included to Chrysalis, only Pollen
  // balance_init(&balan, NULL, 100);
  balance_init(&balan, 100);

  // convert balance to bytes
  balance_2_bytes(balance_byte, &balan);
  // init balance object from bytes
  balance_from_bytes(&balan_exp, balance_byte);

  // expect: balan_exp == balan
  // Note: colored coins are not yet included to Chrysalis, only Pollen
  // TEST_ASSERT_EQUAL_MEMORY(balan_exp.color, balan.color, BALANCE_COLOR_BYTES);
  TEST_ASSERT_EQUAL_UINT64(balan_exp.value, balan.value);

  // Note: colored coins are not yet included to Chrysalis, only Pollen
  /*
  for (int i = 0; i < BALANCE_COLOR_BYTES; i++) {
    color[i] = 0x22;
  }

  balance_set_color(&balan, color);
  TEST_ASSERT_EQUAL_MEMORY(balan.color, color, BALANCE_COLOR_BYTES);
  */
  // print_balance(&balan);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_balance);

  return UNITY_END();
}
