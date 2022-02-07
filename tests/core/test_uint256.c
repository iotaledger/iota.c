// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "core/utils/uint256.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_uint256_from_str() {
  uint256_t *num;
  char *str;

  //=====Test 0 unsigned 256-bit number=====
  num = uint256_from_str("0");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("0", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);

  //=====Test maximum unsigned 256-bit number=====
  num = uint256_from_str("115792089237316195423570985008687907853269984665640564039457584007913129639935");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("115792089237316195423570985008687907853269984665640564039457584007913129639935", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);

  //=====Test overflow of unsigned 256-bit number=====
  num = uint256_from_str("115792089237316195423570985008687907853269984665640564039457584007913129639936");
  TEST_ASSERT_NULL(num);
  free(num);

  //=====Test maximum - 1 unsigned 256-bit number=====
  num = uint256_from_str("115792089237316195423570985008687907853269984665640564039457584007913129639934");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("115792089237316195423570985008687907853269984665640564039457584007913129639934", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);

  //=====Test maximum unsigned 64-bit number=====
  num = uint256_from_str("18446744073709551615");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("18446744073709551615", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);

  //=====Test carry when multiplying unsigned 64-bit number=====
  num = uint256_from_str("36893488147419103232");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("36893488147419103232", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);

  //=====Additional test carry when multiplying unsigned 64-bit number=====
  num = uint256_from_str("36893488147419103235");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("36893488147419103235", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);

  //=====Test "random" unsigned 256-bit number=====
  num = uint256_from_str("5534023222112865484629837493874298");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("5534023222112865484629837493874298", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);

  //=====Additional test "random" unsigned 256-bit number=====
  num = uint256_from_str("553402322345987345876897672398261387023640222112865484629837493874298");
  TEST_ASSERT_NOT_NULL(num);
  str = uint256_to_str(num);
  TEST_ASSERT_EQUAL_STRING("553402322345987345876897672398261387023640222112865484629837493874298", str);
  printf("Created number :%s\n", str);
  free(str);
  free(num);
}

void test_uint256_add() {
  uint256_t num1, num2, num3;
  bool res;
  char *str1, *str2, *str3;

  //=====Test overflow of unsigned 256-bit number=====
  num1.bits[0] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[1] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[2] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[3] = 0x0000000000000000;

  num2.bits[0] = 0x0000000000000001;
  num2.bits[1] = 0x0000000000000000;
  num2.bits[2] = 0x0000000000000000;
  num2.bits[3] = 0x0000000000000000;

  res = uint256_add(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000000, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000000, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000000, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000001, num3.bits[3]);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  str3 = uint256_to_str(&num3);
  printf("%s + %s = %s\n", str1, str2, str3);
  free(str1);
  free(str2);
  free(str3);

  //=====Test addition to get maximum unsigned 256-bit number=====
  num1.bits[0] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[1] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[2] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[3] = 0x7FFFFFFFFFFFFFFF;

  num2.bits[0] = 0x0000000000000000;
  num2.bits[1] = 0x0000000000000000;
  num2.bits[2] = 0x0000000000000000;
  num2.bits[3] = 0x8000000000000000;

  res = uint256_add(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFF, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFF, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFF, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFF, num3.bits[3]);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  str3 = uint256_to_str(&num3);
  printf("%s + %s = %s\n", str1, str2, str3);
  free(str1);
  free(str2);
  free(str3);

  //=====Test addition of two "random" unsigned 256-bit numbers=====
  num1.bits[0] = 0x136CF8C718CD2CED;
  num1.bits[1] = 0x6DBAA3BB90F8B53F;
  num1.bits[2] = 0xAF9F3AC14DF900CD;
  num1.bits[3] = 0x7538DCFB7617FFFF;

  num2.bits[0] = 0xEE3893897C976CBC;
  num2.bits[1] = 0x135A88EBDFB74B3E;
  num2.bits[2] = 0xE4588421EC581538;
  num2.bits[3] = 0x67582647CEB3FFFF;

  res = uint256_add(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0x1A58C50956499A9, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0x81152CA770B0007E, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0x93F7BEE33A511605, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0xDC91034344CBFFFF, num3.bits[3]);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  str3 = uint256_to_str(&num3);
  printf("%s + %s = %s\n", str1, str2, str3);
  free(str1);
  free(str2);
  free(str3);

  //=====Sum is bigger number than maximum unsigned 256-bit number=====
  num1.bits[0] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[1] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[2] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[3] = 0xFFFFFFFFFFFFFFFF;

  num2.bits[0] = 0x0000000000000001;
  num2.bits[1] = 0x0000000000000000;
  num2.bits[2] = 0x0000000000000000;
  num2.bits[3] = 0x0000000000000000;

  res = uint256_add(&num3, &num1, &num2);
  TEST_ASSERT_FALSE(res);
}

void test_uint256_sub() {
  uint256_t num1, num2, num3;
  bool res;
  char *str1, *str2, *str3;

  //=====Test underflow of unsigned 256-bit number=====
  num1.bits[0] = 0x0000000000000000;
  num1.bits[1] = 0x0000000000000000;
  num1.bits[2] = 0x0000000000000000;
  num1.bits[3] = 0x0000000000000001;

  num2.bits[0] = 0xFFFFFFFFFFFFFFFF;
  num2.bits[1] = 0xFFFFFFFFFFFFFFFF;
  num2.bits[2] = 0xFFFFFFFFFFFFFFFF;
  num2.bits[3] = 0x0000000000000000;

  res = uint256_sub(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000001, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000000, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000000, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0x0000000000000000, num3.bits[3]);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  str3 = uint256_to_str(&num3);
  printf("%s - %s = %s\n", str1, str2, str3);
  free(str1);
  free(str2);
  free(str3);

  //=====Test subtraction from maximum unsigned 256-bit number=====
  num1.bits[0] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[1] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[2] = 0xFFFFFFFFFFFFFFFF;
  num1.bits[3] = 0xFFFFFFFFFFFFFFFF;

  num2.bits[0] = 0x0000000000000000;
  num2.bits[1] = 0x0000000000000000;
  num2.bits[2] = 0x0000000000000000;
  num2.bits[3] = 0x8000000000000000;

  res = uint256_sub(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFF, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFF, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0xFFFFFFFFFFFFFFFF, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0x7FFFFFFFFFFFFFFF, num3.bits[3]);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  str3 = uint256_to_str(&num3);
  printf("%s - %s = %s\n", str1, str2, str3);
  free(str1);
  free(str2);
  free(str3);

  //=====Test subtraction of two "random" unsigned 256-bit numbers=====
  num1.bits[0] = 0xE36CF8C718CD2CED;
  num1.bits[1] = 0x6DBAA3BB90F8B53F;
  num1.bits[2] = 0xAF9F3AC14DF900CD;
  num1.bits[3] = 0x7538DCFB7617FFFF;

  num2.bits[0] = 0x7E3893897C976CBC;
  num2.bits[1] = 0x135A88EBDFB74B3E;
  num2.bits[2] = 0xE4588421EC581538;
  num2.bits[3] = 0x67582647CEB3FFFF;

  res = uint256_sub(&num3, &num1, &num2);
  TEST_ASSERT_TRUE(res);
  TEST_ASSERT_EQUAL_UINT64(0x6534653D9C35C031, num3.bits[0]);
  TEST_ASSERT_EQUAL_UINT64(0x5A601ACFB1416A01, num3.bits[1]);
  TEST_ASSERT_EQUAL_UINT64(0xCB46B69F61A0EB95, num3.bits[2]);
  TEST_ASSERT_EQUAL_UINT64(0xDE0B6B3A763FFFF, num3.bits[3]);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  str3 = uint256_to_str(&num3);
  printf("%s - %s = %s\n", str1, str2, str3);
  free(str1);
  free(str2);
  free(str3);

  //=====Subtrahend number is bigger then minuend number=====
  num1.bits[0] = 0xEEEEEEEEEEEEEEEE;
  num1.bits[1] = 0xEEEEEEEEEEEEEEEE;
  num1.bits[2] = 0xEEEEEEEEEEEEEEEE;
  num1.bits[3] = 0xEEEEEEEEEEEEEEEE;

  num2.bits[0] = 0xFFFFFFFFFFFFFFFF;
  num2.bits[1] = 0xFFFFFFFFFFFFFFFF;
  num2.bits[2] = 0xFFFFFFFFFFFFFFFF;
  num2.bits[3] = 0xFFFFFFFFFFFFFFFF;

  res = uint256_sub(&num3, &num1, &num2);
  TEST_ASSERT_FALSE(res);
}

void test_uint256_equal() {
  uint256_t num1, num2;
  int res;
  char *str1, *str2;

  //=====Numbers are equal=====
  num1.bits[0] = 0xE36CF8C718CD2CED;
  num1.bits[1] = 0x6DBAA3BB90F8B53F;
  num1.bits[2] = 0xAF9F3AC14DF900CD;
  num1.bits[3] = 0x7538DCFB7617FFFF;

  num2.bits[0] = 0xE36CF8C718CD2CED;
  num2.bits[1] = 0x6DBAA3BB90F8B53F;
  num2.bits[2] = 0xAF9F3AC14DF900CD;
  num2.bits[3] = 0x7538DCFB7617FFFF;

  res = uint256_equal(&num1, &num2);
  TEST_ASSERT_EQUAL_INT(0, res);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  printf("%s = %s\n", str1, str2);
  free(str1);
  free(str2);

  //=====Numbers are equal (both 0)=====
  num1.bits[0] = 0x0000000000000000;
  num1.bits[1] = 0x0000000000000000;
  num1.bits[2] = 0x0000000000000000;
  num1.bits[3] = 0x0000000000000000;

  num2.bits[0] = 0x0000000000000000;
  num2.bits[1] = 0x0000000000000000;
  num2.bits[2] = 0x0000000000000000;
  num2.bits[3] = 0x0000000000000000;

  res = uint256_equal(&num1, &num2);
  TEST_ASSERT_EQUAL_INT(0, res);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  printf("%s = %s\n", str1, str2);
  free(str1);
  free(str2);

  //=====Numbers are equal=====
  num1.bits[0] = 0x0000000000000001;
  num1.bits[1] = 0x1000000000000000;
  num1.bits[2] = 0x0000000000000001;
  num1.bits[3] = 0x1000000000000000;

  num2.bits[0] = 0x0000000000000001;
  num2.bits[1] = 0x1000000000000000;
  num2.bits[2] = 0x0000000000000001;
  num2.bits[3] = 0x1000000000000000;

  res = uint256_equal(&num1, &num2);
  TEST_ASSERT_EQUAL_INT(0, res);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  printf("%s = %s\n", str1, str2);
  free(str1);
  free(str2);

  //=====num1 is greater than num2=====
  num1.bits[0] = 0xE36CF8C718CD2CEE;
  num1.bits[1] = 0x6DBAA3BB90F8B53F;
  num1.bits[2] = 0xAF9F3AC14DF900CD;
  num1.bits[3] = 0x7538DCFB7617FFFF;

  num2.bits[0] = 0xE36CF8C718CD2CED;
  num2.bits[1] = 0x6DBAA3BB90F8B53F;
  num2.bits[2] = 0xAF9F3AC14DF900CD;
  num2.bits[3] = 0x7538DCFB7617FFFF;

  res = uint256_equal(&num1, &num2);
  TEST_ASSERT_EQUAL_INT(1, res);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  printf("%s > %s\n", str1, str2);
  free(str1);
  free(str2);

  //=====num3 is greater than num4=====
  uint256_t *num3;
  uint256_t *num4;
  num3 = uint256_from_str("30000000000000000000000000000000000000000");
  num4 = uint256_from_str("20000000000000000000000000000000000000000");

  res = uint256_equal(num3, num4);
  TEST_ASSERT_EQUAL_INT(1, res);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  printf("%s > %s\n", str1, str2);
  free(str1);
  free(str2);
  free(num3);
  free(num4);

  //=====num1 is smaller than num2=====
  num1.bits[0] = 0xE36CF8C718CD2CEC;
  num1.bits[1] = 0x6DBAA3BB90F8B53F;
  num1.bits[2] = 0xAF9F3AC14DF900CD;
  num1.bits[3] = 0x7538DCFB7617FFFF;

  num2.bits[0] = 0xE36CF8C718CD2CED;
  num2.bits[1] = 0x6DBAA3BB90F8B53F;
  num2.bits[2] = 0xAF9F3AC14DF900CD;
  num2.bits[3] = 0x7538DCFB7617FFFF;

  res = uint256_equal(&num1, &num2);
  TEST_ASSERT_EQUAL_INT(-1, res);
  str1 = uint256_to_str(&num1);
  str2 = uint256_to_str(&num2);
  printf("%s < %s\n", str1, str2);
  free(str1);
  free(str2);
}

void test_uint256_to_str() {
  uint256_t num;
  char *str;

  //=====Maximum value of an unsigned 256-bit number=====
  num.bits[0] = 0xFFFFFFFFFFFFFFFF;
  num.bits[1] = 0xFFFFFFFFFFFFFFFF;
  num.bits[2] = 0xFFFFFFFFFFFFFFFF;
  num.bits[3] = 0xFFFFFFFFFFFFFFFF;

  str = uint256_to_str(&num);
  TEST_ASSERT_NOT_NULL(str);
  TEST_ASSERT_EQUAL_STRING("115792089237316195423570985008687907853269984665640564039457584007913129639935", str);
  printf("Max 256-bit number: %s\n", str);
  free(str);

  //=====Zero unsigned 256-bit number=====
  num.bits[0] = 0x0000000000000000;
  num.bits[1] = 0x0000000000000000;
  num.bits[2] = 0x0000000000000000;
  num.bits[3] = 0x0000000000000000;

  str = uint256_to_str(&num);
  TEST_ASSERT_NOT_NULL(str);
  TEST_ASSERT_EQUAL_STRING("0", str);
  printf("Zero 256-bit number: %s\n", str);
  free(str);

  //=====Small unsigned 256-bit number=====
  num.bits[0] = 0xE36CF8C718CD2CED;
  num.bits[1] = 0x0000000000000000;
  num.bits[2] = 0x6DBAA3BB90F8B53F;
  num.bits[3] = 0x0000000000000000;

  str = uint256_to_str(&num);
  TEST_ASSERT_NOT_NULL(str);
  TEST_ASSERT_EQUAL_STRING("2690548743601445896320600757642964677162741715297406627053", str);
  printf("Small 256-bit number: %s\n", str);
  free(str);

  //====="Random" unsigned 256-bit number=====
  num.bits[0] = 0xE36CF8C718CD2CED;
  num.bits[1] = 0x6DBAA3BB90F8B53F;
  num.bits[2] = 0xAF9F3AC14DF900CD;
  num.bits[3] = 0x7538DCFB7617FFFF;

  str = uint256_to_str(&num);
  TEST_ASSERT_NOT_NULL(str);
  TEST_ASSERT_EQUAL_STRING("53021071883449387783242227712977678841266351175989414378504472453946362637549", str);
  printf("\"Random\" 256-bit number: %s\n", str);
  free(str);
}

void test_uint256_clone() {
  //=====NULL unsigned 256-bit number=====
  uint256_t *new_num = uint256_clone(NULL);
  TEST_ASSERT_NULL(new_num);

  //====="Random" unsigned 256-bit number=====
  uint256_t num;
  num.bits[0] = 0xE36CF8C718CD2CED;
  num.bits[1] = 0x6DBAA3BB90F8B53F;
  num.bits[2] = 0xAF9F3AC14DF900CD;
  num.bits[3] = 0x7538DCFB7617FFFF;

  new_num = uint256_clone(&num);
  TEST_ASSERT_NOT_NULL(new_num);
  TEST_ASSERT_EQUAL_MEMORY(num.bits, new_num->bits, sizeof(num.bits));

  free(new_num);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_uint256_from_str);
  RUN_TEST(test_uint256_add);
  RUN_TEST(test_uint256_sub);
  RUN_TEST(test_uint256_equal);
  RUN_TEST(test_uint256_to_str);
  RUN_TEST(test_uint256_clone);

  return UNITY_END();
}
