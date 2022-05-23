// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_UINT256_H__
#define __CORE_UTILS_UINT256_H__

#include <stdbool.h>
#include <stdint.h>

// Maximum possible length of a string representing 256-bit number. 78 characters + string termination character
#define STRING_NUMBER_MAX_CHARACTERS 79

/**
 * @brief A 256 bit number object.
 *
 * Custom implementation for 256 bit number representation.
 * Only a little endian format is supported at the moment.
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
 * @param[in] str A c_string representing a 256 bit number.
 * @return uint256_t* Pointer to uint256 object, NULL on failed.
 */
uint256_t *uint256_from_str(char const *str);

/**
 * @brief New uint256 object from hex c_string representing a 256 bit number.
 *
 * @param[in] str A hex c_string representing a 256 bit number.
 * @return uint256_t* Pointer to uint256 object, NULL on failed.
 */
uint256_t *uint256_from_hex_str(char const *str);

/**
 * @brief Perform addition on two uint256 numbers.
 *
 * @param[out] sum The sum of two numbers.
 * @param[in] a The summand A.
 * @param[in] b The summand B.
 * @return true On success
 * @return false On failed
 */
bool uint256_add(uint256_t *sum, uint256_t *a, uint256_t *b);

/**
 * @brief Perform subtraction on two uint256 numbers.
 *
 * @param[out] diff The difference of two numbers.
 * @param[in] min The minuend.
 * @param[in] sub The subtrahend.
 * @return true On success
 * @return false On failed
 */
bool uint256_sub(uint256_t *diff, uint256_t *min, uint256_t *sub);

/**
 * @brief Compare two uint256 objects (numbers)
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

/**
 * @brief Converts uint256 number to a hex string
 *
 * @param[in] num A pointer to uint256 object
 * @return Pointer to string object, NULL on failed.
 */
char *uint256_to_hex_str(uint256_t *num);

/**
 * @brief Clone uint256 object, it should be freed after use.
 *
 * @param[in] num A pointer to uint256 object for clone
 * @return uint256_t* New uint256 object
 */
uint256_t *uint256_clone(uint256_t const *const num);

/**
 * @brief Free a unit256_t object
 *
 * @param[in] num A pointer to uint256 object
 */
void uint256_free(uint256_t *num);

#ifdef __cplusplus
}
#endif

#endif
