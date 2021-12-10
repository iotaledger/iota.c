// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/utils/uint256.h"

#define STRING_NUMBER_MAX_CHARACTERS 79  // 78 characters + string termination character

uint256_t *uint256_from_str(char const *s) {
  uint256_t *num = (uint256_t *)malloc(sizeof(uint256_t));
  if (!num) {
    return NULL;
  }

  memset(num, 0, sizeof(uint256_t));

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
  if ((res->bits[0] < num1->bits[0]) || (res->bits[0] < num2->bits[0])) {
    res->bits[1] += 1;
  }

  res->bits[2] = num1->bits[2] + num2->bits[2];
  if ((res->bits[1] < num1->bits[1]) || (res->bits[1] < num2->bits[1])) {
    res->bits[2] += 1;
  }

  res->bits[3] = num1->bits[3] + num2->bits[3];
  if ((res->bits[2] < num1->bits[2]) || (res->bits[2] < num2->bits[2])) {
    res->bits[3] += 1;
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
  if (res->bits[0] > num1->bits[0]) {
    res->bits[1] -= 1;
  }

  res->bits[2] = num1->bits[2] - num2->bits[2];
  if (res->bits[1] > num1->bits[1]) {
    res->bits[2] -= 1;
  }

  res->bits[3] = num1->bits[3] - num2->bits[3];
  if (res->bits[2] > num1->bits[2]) {
    res->bits[3] -= 1;
  }

  return true;
}

int uint256_equal(uint256_t const *num1, uint256_t const *num2) {
  if (num1 == NULL || num2 == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }
  // TODO implementation is needed
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
    int carry = temp_num.bits[3] >= 0x8000000000000000;

    // Shift temp_num left, doubling it
    temp_num.bits[3] = ((temp_num.bits[3] << 1) & 0xFFFFFFFFFFFFFFFF) + (temp_num.bits[2] >= 0x8000000000000000);
    temp_num.bits[2] = ((temp_num.bits[2] << 1) & 0xFFFFFFFFFFFFFFFF) + (temp_num.bits[1] >= 0x8000000000000000);
    temp_num.bits[1] = ((temp_num.bits[1] << 1) & 0xFFFFFFFFFFFFFFFF) + (temp_num.bits[0] >= 0x8000000000000000);
    temp_num.bits[0] = ((temp_num.bits[0] << 1) & 0xFFFFFFFFFFFFFFFF);

    // Add str_temp to itself in decimal, doubling it
    for (int8_t j = STRING_NUMBER_MAX_CHARACTERS - 2; j >= 0; j--) {
      str_temp[j] += str_temp[j] - '0' + carry;

      carry = (str_temp[j] > '9');

      if (carry) {
        str_temp[j] -= 10;
      }
    }
  }

  // Count leading zeros in a temporary string
  uint8_t count_zeros = 0;
  while ((str_temp[count_zeros] == '0') && (count_zeros < STRING_NUMBER_MAX_CHARACTERS)) {
    count_zeros++;
  }

  // Create a string with appropirate length
  char *str = malloc(STRING_NUMBER_MAX_CHARACTERS - count_zeros);
  memcpy(str, str_temp + count_zeros, STRING_NUMBER_MAX_CHARACTERS - count_zeros);

  return str;
}
