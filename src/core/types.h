// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_TYPES_H__
#define __CORE_TYPES_H__

#include <stdint.h>
#include <stdio.h>

typedef uint8_t byte_t;
typedef uint32_t payload_t;
typedef uint8_t output_t;
typedef uint8_t input_t;
typedef uint8_t transaction_t;
typedef uint8_t signature_t;
typedef uint16_t unlock_index_t;

/* clang-format off */
/**
 * @brief Returns string representing tabulator indentation
 *
 * @param[in] i Indentation level. The range of i is between 0 and 5.
 */
#define PRINT_INDENTATION(i)   \
  ((i) == 0   ? "\0"           \
   : (i) == 1 ? "\t\0"         \
   : (i) == 2 ? "\t\t\0"       \
   : (i) == 3 ? "\t\t\t\0"     \
   : (i) == 4 ? "\t\t\t\t\0"   \
   : (i) == 5 ? "\t\t\t\t\t\0" \
              : "\0")
/* clang-format on */

/**
 * @brief Prints out hexmal value in a byte array.
 *
 * @param[in] data A byte_t buffer
 * @param[in] len The length of data
 */
static inline void dump_hex(byte_t const data[], size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("0x%x, ", data[i]);
  }
  printf("\n");
}

/**
 * @brief Prints out hexmal value in a string.
 *
 * @param[in] data A byte_t buffer
 * @param[in] len The length of data
 */
static inline void dump_hex_str(byte_t const data[], size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%.2x", data[i]);
  }
  printf("\n");
}

#endif
