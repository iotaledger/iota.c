#ifndef __CORE_TYPES_H__
#define __CORE_TYPES_H__

#include <stdint.h>
#include <stdio.h>

typedef uint8_t byte_t;
typedef uint32_t payload_t;
typedef uint8_t output_t;
typedef uint8_t input_t;
typedef uint8_t transaction_t;
typedef uint8_t unlock_block_t;
typedef uint8_t signature_t;

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

#endif