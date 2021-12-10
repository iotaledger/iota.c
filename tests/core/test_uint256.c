// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/utils/uint256.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_uint256_add() {
  uint256_t num1 = {0};
  num1.bits[0] = 0x136CF8C718CD2CED;
  num1.bits[1] = 0x6DBAA3BB90F8B53F;
  num1.bits[2] = 0xAF9F3AC14DF900CD;
  num1.bits[3] = 0x7538DCFB7617FFFF;
  uint256_t num2 = {0};
  num2.bits[0] = 0xEE3893897C976CBC;
  num2.bits[1] = 0x135A88EBDFB74B3E;
  num2.bits[2] = 0xE4588421EC581538;
  num2.bits[3] = 0x67582647CEB3FFFF;

  uint256_t num3 = {0};
  bool res = uint256_add(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0x1A58C50956499A9, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0x81152CA770B0007E, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0x93F7BEE33A511605, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0xDC91034344CBFFFF, num3.bits[3]);
}

void test_uint256_sub() {
  uint256_t num1 = {0};
  num1.bits[0] = 0xE36CF8C718CD2CED;
  num1.bits[1] = 0x6DBAA3BB90F8B53F;
  num1.bits[2] = 0xAF9F3AC14DF900CD;
  num1.bits[3] = 0x7538DCFB7617FFFF;
  uint256_t num2 = {0};
  num2.bits[0] = 0x7E3893897C976CBC;
  num2.bits[1] = 0x135A88EBDFB74B3E;
  num2.bits[2] = 0xE4588421EC581538;
  num2.bits[3] = 0x67582647CEB3FFFF;

  uint256_t num3 = {0};
  bool res = uint256_sub(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0x6534653D9C35C031, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0x5A601ACFB1416A01, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0xCB46B69F61A0EB95, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0xDE0B6B3A763FFFF, num3.bits[3]);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_uint256_add);
  RUN_TEST(test_uint256_sub);

  return UNITY_END();
}
