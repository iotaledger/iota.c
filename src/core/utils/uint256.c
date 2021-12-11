// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/utils/uint256.h"

#define hi(x) (x >> 32)
#define lo(x) ((((uint64_t)0x1 << 32) - 1) & x)

#define STRING_NUMBER_MAX_CHARACTERS 79  // 78 characters + string termination character

static void multiply64(uint64_t a, uint64_t b, uint64_t *result, uint64_t *carry) {
  uint64_t s0, s1, s2, s3;

  uint64_t x = lo(a) * lo(b);
  s0 = lo(x);

  x = hi(a) * lo(b) + hi(x);
  s1 = lo(x);
  s2 = hi(x);

  x = s1 + lo(a) * hi(b);
  s1 = lo(x);

  x = s2 + hi(a) * hi(b) + hi(x);
  s2 = lo(x);
  s3 = hi(x);

  *result = s1 << 32 | s0;
  *carry = s3 << 32 | s2;
}

uint256_t *uint256_from_str(char const *s) {
  if (s == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  uint256_t *num = (uint256_t *)malloc(sizeof(uint256_t));
  if (!num) {
    printf("[%s:%d] creating uint256 object failed\n", __func__, __LINE__);
    return NULL;
  }

  memset(num, 0, sizeof(uint256_t));

  uint64_t result = 0;
  uint64_t carry_part0 = 0;
  uint64_t carry_part1 = 0;
  uint64_t carry_part2 = 0;
  uint64_t carry_part3 = 0;

  bool overflow_part0 = false;
  bool overflow_part1 = false;
  bool overflow_part2 = false;

  for (uint8_t i = 0; i < strlen(s); i++) {
    multiply64(10, num->bits[0], &result, &carry_part0);
    num->bits[0] = result + (s[i] - '0');

    if (carry_part0 > 0 || num->bits[0] < result) {
      overflow_part0 = true;

      if (num->bits[0] < result) {
        carry_part0++;
      }
    }

    if (overflow_part0) {
      multiply64(10, num->bits[1], &result, &carry_part1);
      num->bits[1] = result;

      if (carry_part0) {
        num->bits[1] += carry_part0;
      }

      if (carry_part1 > 0 || num->bits[1] < result) {
        overflow_part1 = true;

        if (num->bits[1] < result) {
          carry_part1++;
        }
      }
    }

    if (overflow_part1) {
      multiply64(10, num->bits[2], &result, &carry_part2);
      num->bits[2] = result;

      if (carry_part1) {
        num->bits[2] += carry_part1;
      }

      if (carry_part2 > 0 || num->bits[2] < result) {
        overflow_part2 = true;

        if (num->bits[2] < result) {
          carry_part2++;
        }
      }
    }

    if (overflow_part2) {
      multiply64(10, num->bits[3], &result, &carry_part3);
      num->bits[3] = result;

      if (carry_part2) {
        num->bits[3] += carry_part2;
      }

      if (carry_part3 > 0 || num->bits[3] < result) {
        printf("[%s:%d] Overflow occurs. Given string number is too large.\n", __func__, __LINE__);
        free(num);
        return NULL;
      }
    }
  }

  return num;
}

bool uint256_add(uint256_t *res, uint256_t *num1, uint256_t *num2) {
  if (res == NULL || num1 == NULL || num2 == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  res->bits[0] = num1->bits[0] + num2->bits[0];

  res->bits[1] = num1->bits[1] + num2->bits[1];
  if (res->bits[0] < num1->bits[0]) {
    res->bits[1] += 1;
  }

  res->bits[2] = num1->bits[2] + num2->bits[2];
  if (res->bits[1] < num1->bits[1]) {
    res->bits[2] += 1;
  }

  res->bits[3] = num1->bits[3] + num2->bits[3];
  if (res->bits[2] < num1->bits[2]) {
    res->bits[3] += 1;
  }

  if (res->bits[3] < num1->bits[3]) {
    printf("[%s:%d] Overflow occurs. Summed number is too large.\n", __func__, __LINE__);
    return false;
  }

  return true;
}

bool uint256_sub(uint256_t *res, uint256_t *num1, uint256_t *num2) {
  if (res == NULL || num1 == NULL || num2 == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  res->bits[0] = num1->bits[0] - num2->bits[0];

  res->bits[1] = num1->bits[1] - num2->bits[1];
  if (num2->bits[0] > num1->bits[0]) {
    res->bits[1] -= 1;
  }

  res->bits[2] = num1->bits[2] - num2->bits[2];
  if (num2->bits[1] > num1->bits[1]) {
    res->bits[2] -= 1;
  }

  res->bits[3] = num1->bits[3] - num2->bits[3];
  if (num2->bits[2] > num1->bits[2]) {
    res->bits[3] -= 1;
  }

  if (num2->bits[3] > num1->bits[3]) {
    printf("[%s:%d] Underflow occurs. Subtracted number is too small.\n", __func__, __LINE__);
    return false;
  }

  return true;
}

int uint256_equal(uint256_t const *num1, uint256_t const *num2) {
  if (num1 == NULL || num2 == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  return memcmp(num1, num2, sizeof(uint256_t));
}

char *uint256_to_str(uint256_t *num) {
  if (num == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  char str_temp[STRING_NUMBER_MAX_CHARACTERS];
  memset(str_temp, '0', sizeof(str_temp) - 1);
  str_temp[sizeof(str_temp) - 1] = '\0';

  uint256_t temp_num = *num;

  for (uint16_t i = 0; i < 256; i++) {
    uint8_t carry = temp_num.bits[3] >= 0x8000000000000000;

    // shift temp_num left, doubling it
    temp_num.bits[3] = ((temp_num.bits[3] << 1) & 0xFFFFFFFFFFFFFFFF) + (temp_num.bits[2] >= 0x8000000000000000);
    temp_num.bits[2] = ((temp_num.bits[2] << 1) & 0xFFFFFFFFFFFFFFFF) + (temp_num.bits[1] >= 0x8000000000000000);
    temp_num.bits[1] = ((temp_num.bits[1] << 1) & 0xFFFFFFFFFFFFFFFF) + (temp_num.bits[0] >= 0x8000000000000000);
    temp_num.bits[0] = ((temp_num.bits[0] << 1) & 0xFFFFFFFFFFFFFFFF);

    // add str_temp to itself in decimal, doubling it
    for (int8_t j = STRING_NUMBER_MAX_CHARACTERS - 2; j >= 0; j--) {
      str_temp[j] += str_temp[j] - '0' + carry;
      carry = (str_temp[j] > '9');
      if (carry) {
        str_temp[j] -= 10;
      }
    }
  }

  // count leading zeros in a temporary string
  uint8_t count_zeros = 0;
  while ((str_temp[count_zeros] == '0') && (count_zeros < (STRING_NUMBER_MAX_CHARACTERS - 2))) {
    count_zeros++;
  }

  // create a string with appropriate length
  char *str = (char *)malloc(STRING_NUMBER_MAX_CHARACTERS - count_zeros);
  if (!str) {
    printf("[%s:%d] allocation memory space for string failed\n", __func__, __LINE__);
    return NULL;
  }
  memcpy(str, str_temp + count_zeros, STRING_NUMBER_MAX_CHARACTERS - count_zeros);

  return str;
}
