// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_UINT256_H__
#define __CORE_UTILS_UINT256_H__

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief A 256 bit number object.
 *
 */
typedef struct {
  uint64_t bits[4];  ///< 256 bit number represented in a little endian format
} uint256_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief New uint256 object from c_string representing a 256 bit number.
 *
 * @param[in] s A c_string representing a 256 bit number.
 * @return uint256_t* Pointer to uint256 object, NULL on failed.
 */
uint256_t *uint256_from_str(char const *s);

/**
 * @brief Perform addition on two uint256 numbers.
 *
 * @param[out] res Sum of two numbers. A pointer to uint256 object
 * @param[in] a Summand. A pointer to uint256 object
 * @param[in] b Summand. A pointer to uint256 object
 * @return true On success
 * @return false On failed
 */
bool uint256_add(uint256_t *res, uint256_t *a, uint256_t *b);

/**
 * @brief Perform subtraction on two uint256 numbers.
 *
 * @param[out] res Difference of two numbers. A pointer to uint256 object
 * @param[in] a Minuend. A pointer to uint256 object
 * @param[in] b Subtrahend. A pointer to uint256 object
 * @return true On success
 * @return false On failed
 */
bool uint256_sub(uint256_t *res, uint256_t *a, uint256_t *b);

/**
 * @brief Compare two uint256 objects (numbers)
 *
 * Comparing NULL uint256 objects is undefined behaviour.
 *
 * @param[in] a A pointer to uint256 object
 * @param[in] b A pointer to uint256 object
 * @return int < 0 if a is smaller then b
 * @return int > 0 if a is greater than b
 * @return int 0 if a is equal to b
 */
int uint256_equal(uint256_t const *a, uint256_t const *b);

/**
 * @brief Converts uint256 number to a string
 *
 * @param[in] num A pointer to uint256 object
 * @return Pointer to string object, NULL on failed.
 */
char *uint256_to_str(uint256_t *num);

#ifdef __cplusplus
}
#endif

#endif
