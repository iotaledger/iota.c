// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_IOTA_STR_H__
#define __CORE_UTILS_IOTA_STR_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief A mutable string buffer.
 *
 */
typedef struct {
  char *buf;  /**< string pointer */
  size_t cap; /**< allocated capacity */
  size_t len; /**< string length */
} iota_str_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief New a string object from c_string.
 *
 * @param[in] s A c_string
 * @return iota_str_t* The pointer to string object, NULL on failed.
 */
iota_str_t *iota_str_new(char const *s);

/**
 * @brief Appends a sized c_string
 *
 * @param[out] istr A pointer to a string object
 * @param[in] s A c_string
 * @param[in] len the size of characters
 * @return int 0 on success
 */
int iota_str_appendn(iota_str_t *istr, char const s[], size_t len);

/**
 * @brief Appends a c_string
 *
 * @param[out] istr A pointer to a string object
 * @param[in] s A c_string
 * @return int 0 on success
 */
static inline int iota_str_append(iota_str_t *istr, char const s[]) { return iota_str_appendn(istr, s, strlen(s)); }

/**
 * @brief Appends a char
 *
 * @param[out] istr A pointer to a string object
 * @param[in] c A character
 * @return int 0 on success
 */
static inline int iota_str_append_char(iota_str_t *istr, char c) { return iota_str_appendn(istr, &c, 1); }

/**
 * @brief Deallocates the string object
 *
 * @param[in] istr the string object
 */
void iota_str_destroy(iota_str_t *istr);

/**
 * @brief Clones a string with a length
 *
 * @param[in] istr A pointer to a string object
 * @param[in] len the length for clone
 * @return iota_str_t* A cloned string object
 */
iota_str_t *iota_str_clonen(iota_str_t *istr, size_t len);

/**
 * @brief Clones a string object
 *
 * @param[in] istr A pointer to a string object
 * @return iota_str_t* A cloned string object
 */
static inline iota_str_t *iota_str_clone(iota_str_t *istr) { return iota_str_clonen(istr, istr->len); }

/**
 * @brief Compare two strings
 *
 * Comparing NULL string or string without null terminator are undefined behaviours.
 *
 * @param[in] a string A
 * @param[in] b string B
 * @return int
 */
static inline int iota_str_cmp(iota_str_t const *a, iota_str_t const *b) { return strcmp(a->buf, b->buf); };

/**
 * @brief New a string object and reserves a specific length
 *
 * @param[in] len the length to reserve
 * @return iota_str_t*
 */
iota_str_t *iota_str_reserve(size_t len);

#ifdef __cplusplus
}
#endif

#endif
