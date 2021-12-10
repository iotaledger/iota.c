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
  uint64_t bits[4];  ///< 256 bit number presented in a little endian format
} uint256_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief New uint256 object from c_string representing a 256 bit number.
 *
 * @param[in] s A c_string representing a 256 bit number.
 * @return uint256_t* The pointer to uint256 object, NULL on failed.
 */
uint256_t *uint256_from_str(char const *s);

/**
 * @brief Perform addition on two uint256 numbers.
 *
 * @param[out] res Result. A pointer to a uint256 object
 * @param[in] num1 A pointer to a uint256 object
 * @param[in] num2 A pointer to a uint256 object
 * @return true On success
 * @return false On failed
 */
bool uint256_add(uint256_t *res, uint256_t *num1, uint256_t *num2);

/**
 * @brief Perform subtraction on two uint256 numbers.
 *
 * @param[out] res Result. A pointer to a uint256 object
 * @param[in] num1 A pointer to a uint256 object
 * @param[in] num2 A pointer to a uint256 object
 * @return true On success
 * @return false On failed
 */
bool uint256_sub(uint256_t *res, uint256_t *num1, uint256_t *num2);

/**
 * @brief Compare two uint256 objects (numbers)
 *
 * Comparing NULL uint256 objects is undefined behaviour.
 *
 * @param[in] num1 A pointer to a uint256 object
 * @param[in] num2 A pointer to a uint256 object
 * @return int
 */
int uint256_equal(uint256_t const *num1, uint256_t const *num2);

/**
 * @brief Converts uint256 number to string
 *
 * @param[in] num A pointer to a uint256 object
 * @return The pointer to string object, NULL on failed.
 */
char *uint256_to_str(uint256_t *num);

#ifdef __cplusplus
}
#endif

#endif
