// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_BYTE_BUFFER_H__
#define __CORE_UTILS_BYTE_BUFFER_H__

#include <stdbool.h>
#include <stdlib.h>

#include "core/types.h"

/**
 * @brief byte buffer object
 *
 */
typedef struct {
  size_t len;    ///< the length of data
  size_t cap;    ///< the capacity of this object
  byte_t* data;  ///< a pointer to the data
} byte_buf_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates data buffer
 *
 * @return byte_buf_t*
 */
byte_buf_t* byte_buf_new();

/**
 * @brief Allocates data buffer with given data
 *
 * @param[in] data Inital data
 * @param[in] len The size of data
 * @return byte_buf_t*
 */
byte_buf_t* byte_buf_new_with_data(byte_t data[], size_t len);

/**
 * @brief Appends data to buffer
 *
 * @param[in] buf A buffer object
 * @param[in] data The data for appending
 * @param[in] len The size of data
 * @return true On success
 * @return false On failed
 */
bool byte_buf_append(byte_buf_t* buf, byte_t const data[], size_t len);

/**
 * @brief Sets data to the buffer
 *
 * @param[in] buf A buffer object
 * @param[in] data The data to set
 * @param[in] len The length of data
 * @return true On success
 * @return false On failed
 */
bool byte_buf_set(byte_buf_t* buf, byte_t const data[], size_t len);

/**
 * @brief Frees data buffer
 *
 * @param[in] buf A byte buffer object
 */
void byte_buf_free(byte_buf_t* buf);

/**
 * @brief Converts byte buffer to string
 *
 * @param[out] buf A byte buffer object
 * @return true
 * @return false
 */
bool byte_buf2str(byte_buf_t* buf);

/**
 * @brief Duplicates N bytes from buffer
 *
 * @param[in] buf A byte buffer
 * @param[in] length The cloned length
 * @return byte_buf_t*
 */
byte_buf_t* byte_buf_clonen(byte_buf_t* buf, size_t length);

/**
 * @brief Duplicates a byte buffer
 *
 * @param[in] buf A byte buffer
 * @return byte_buf_t*
 */
static byte_buf_t* byte_buf_clone(byte_buf_t* buf) { return byte_buf_clonen(buf, buf->len); };

/**
 * @brief Changes the buffer capacity
 *
 * @param[in] buf A byte buffer
 * @param[in] len The expect size of this buffer
 * @return true On success
 * @return false On failed
 */
bool byte_buf_reserve(byte_buf_t* buf, size_t len);

/**
 * @brief Dumps buffer infomation for debug propose
 *
 * @param[in] buf A byte buffer
 */
void byte_buf_print(byte_buf_t* buf);

/**
 * @brief Duplicates and converts the data from bin to hex string, the returned object need to be freed.
 *
 * @param[in] buf A byte buffer
 * @return byte_buf_t*
 */
byte_buf_t* byte_buf_str2hex(byte_buf_t* buf);

/**
 * @brief Duplicates and converts the data from hex to text, the returned object need to be freed.
 *
 * @param[in] hex A byte buffer
 * @return byte_buf_t*
 */
byte_buf_t* byte_buf_hex2str(byte_buf_t* hex);

/**
 * @brief Converts a hex string to C string, "48656c6c6f" -> "Hello"
 *
 * @param[in] str A hex string
 * @param[out] array An output buffer holds text data
 * @param[in] arr_len The length of text buffer
 * @return int 0 on success
 */
int hex2string(char const str[], uint8_t array[], size_t arr_len);

/**
 * @brief Converts a text to hex string, "Hello" -> "48656c6c6f"
 *
 * @param[in] str A text string
 * @param[out] hex The hex string from text
 * @param[in] hex_len The length of hex buffer
 * @return int 0 on success
 */
int string2hex(char const str[], byte_t hex[], size_t hex_len);

/**
 * @brief Converts hex string to a byte array
 *
 * @param[in] str A hex string
 * @param[in] str_len The length of the hex string
 * @param[out] bin A byte array buffer
 * @param[in] bin_len The length of byte array
 * @return int 0 on success
 */
int hex_2_bin(char const str[], size_t str_len, byte_t bin[], size_t bin_len);

/**
 * @brief Converts a byte array to hex string
 *
 * @param[in] bin A byte array
 * @param[in] bin_len The length of byte array
 * @param[out] str_buf A buffer holds hex string data
 * @param[in] buf_len The length of the buffer
 * @return int 0 on success
 */
int bin_2_hex(byte_t const bin[], size_t bin_len, char str_buf[], size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif
