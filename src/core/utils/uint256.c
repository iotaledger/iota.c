// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/utils/uint256.h"

// Helper functions to get higher and lower part of an uint64_t number
#define hi(x) (x >> 32)
#define lo(x) ((((uint64_t)0x1 << 32) - 1) & x)

// This function is optimized for multiplying an uint64_t number with 10
static void multiply_by_10(uint64_t *b, uint64_t *result, uint64_t *carry) {
  uint64_t s0, s1, s2, s3;

  uint64_t x = 10 * lo(*b);
  s0 = lo(x);

  x = hi(x);
  s1 = lo(x);
  s2 = hi(x);

  x = s1 + 10 * hi(*b);
  s1 = lo(x);

  x = s2 + hi(x);
  s2 = lo(x);
  s3 = hi(x);

  *result = s1 << 32 | s0;
  *carry = s3 << 32 | s2;
}

uint256_t *uint256_from_str(char const *str) {
  if (str == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  uint256_t *num = malloc(sizeof(uint256_t));
  if (!num) {
    printf("[%s:%d] creating uint256 object failed\n", __func__, __LINE__);
    return NULL;
  }

  memset(num, 0, sizeof(uint256_t));

  uint64_t carry[4] = {0};
  bool overflow[4] = {false};
  uint64_t result = 0;

  for (uint8_t i = 0; i < strlen(str); i++) {
    for (uint8_t j = 0; j < 4; j++) {
      if (j == 0) {
        multiply_by_10(&num->bits[j], &result, &carry[j]);
        num->bits[j] = result + (str[i] - '0');

        if (carry[j] > 0) {
          // multiplication overflows
          overflow[j + 1] = true;
        }

        if (num->bits[j] < result) {
          // addition overflows
          overflow[j + 1] = true;
          carry[j]++;
        }
      } else {
        if (overflow[j]) {
          multiply_by_10(&num->bits[j], &result, &carry[j]);
          num->bits[j] = result;

          if (carry[j] > 0) {
            // multiplication overflows
            if (j == 3) {
              printf("[%s:%d] Overflow occurs. Given string number is too large.\n", __func__, __LINE__);
              free(num);
              return NULL;
            }
            overflow[j + 1] = true;
          }

          if (carry[j - 1]) {
            // carry from previous part of a number must be added because overflow of that part occurs
            num->bits[j] += carry[j - 1];

            if (num->bits[j] < carry[j - 1]) {
              // addition overflows
              if (j == 3) {
                printf("[%s:%d] Overflow occurs. Given string number is too large.\n", __func__, __LINE__);
                free(num);
                return NULL;
              }
              overflow[j + 1] = true;
              carry[j]++;
            }
          }
        }
      }
    }
  }

  return num;
}

bool uint256_add(uint256_t *res, uint256_t *a, uint256_t *b) {
  if (res == NULL || a == NULL || b == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  res->bits[0] = a->bits[0] + b->bits[0];

  res->bits[1] = a->bits[1] + b->bits[1];
  if (res->bits[0] < a->bits[0]) {
    res->bits[1] += 1;
  }

  res->bits[2] = a->bits[2] + b->bits[2];
  if (res->bits[1] < a->bits[1]) {
    res->bits[2] += 1;
  }

  res->bits[3] = a->bits[3] + b->bits[3];
  if (res->bits[2] < a->bits[2]) {
    res->bits[3] += 1;
  }

  if (res->bits[3] < a->bits[3]) {
    printf("[%s:%d] Overflow occurs. Summed number is too large.\n", __func__, __LINE__);
    return false;
  }

  return true;
}

bool uint256_sub(uint256_t *res, uint256_t *a, uint256_t *b) {
  if (res == NULL || a == NULL || b == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  res->bits[0] = a->bits[0] - b->bits[0];

  res->bits[1] = a->bits[1] - b->bits[1];
  if (b->bits[0] > a->bits[0]) {
    res->bits[1] -= 1;
  }

  res->bits[2] = a->bits[2] - b->bits[2];
  if (b->bits[1] > a->bits[1]) {
    res->bits[2] -= 1;
  }

  res->bits[3] = a->bits[3] - b->bits[3];
  if (b->bits[2] > a->bits[2]) {
    res->bits[3] -= 1;
  }

  if (b->bits[3] > a->bits[3]) {
    printf("[%s:%d] Underflow occurs. Subtracted number is too small.\n", __func__, __LINE__);
    return false;
  }

  return true;
}

int uint256_equal(uint256_t const *a, uint256_t const *b) {
  if (a == NULL || b == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  // little endian comparison
  for (int8_t i = 3; i >= 0; i--) {
    if (a->bits[i] != b->bits[i]) {
      return memcmp(&a->bits[i], &b->bits[i], sizeof(uint64_t));
    }
  }

  return 0;
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

  uint256_t num_temp = *num;

  for (uint16_t i = 0; i < 256; i++) {
    uint8_t carry = num_temp.bits[3] >= 0x8000000000000000;

    // shift num_temp left, doubling it
    num_temp.bits[3] = ((num_temp.bits[3] << 1) & 0xFFFFFFFFFFFFFFFF) + (num_temp.bits[2] >= 0x8000000000000000);
    num_temp.bits[2] = ((num_temp.bits[2] << 1) & 0xFFFFFFFFFFFFFFFF) + (num_temp.bits[1] >= 0x8000000000000000);
    num_temp.bits[1] = ((num_temp.bits[1] << 1) & 0xFFFFFFFFFFFFFFFF) + (num_temp.bits[0] >= 0x8000000000000000);
    num_temp.bits[0] = ((num_temp.bits[0] << 1) & 0xFFFFFFFFFFFFFFFF);

    // add str_temp to itself in decimal, doubling it
    for (int8_t j = STRING_NUMBER_MAX_CHARACTERS - 2; j >= 0; j--) {
      str_temp[j] += str_temp[j] - '0' + carry;
      carry = (str_temp[j] > '9');
      if (carry) {
        str_temp[j] -= 10;
      }
    }
  }

  // Count leading zeros in a temporary string. At least one character and string termination character must be present.
  uint8_t count_zeros = 0;
  while ((str_temp[count_zeros] == '0') && (count_zeros < (STRING_NUMBER_MAX_CHARACTERS - 2))) {
    count_zeros++;
  }

  // create a string with appropriate length
  char *str = malloc(STRING_NUMBER_MAX_CHARACTERS - count_zeros);
  if (!str) {
    printf("[%s:%d] allocation memory space for string failed\n", __func__, __LINE__);
    return NULL;
  }
  memcpy(str, str_temp + count_zeros, STRING_NUMBER_MAX_CHARACTERS - count_zeros);

  return str;
}

uint256_t *uint256_clone(uint256_t const *const num) {
  if (num == NULL) {
    return NULL;
  }

  uint256_t *new_num = malloc(sizeof(uint256_t));
  if (new_num) {
    memcpy(new_num->bits, num->bits, sizeof(uint64_t) * 4);
  }

  return new_num;
}
