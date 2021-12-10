// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/utils/uint256.h"

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
