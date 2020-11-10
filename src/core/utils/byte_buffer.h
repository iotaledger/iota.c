#ifndef __CORE_UTILS_BYTE_BUFFER_H__
#define __CORE_UTILS_BYTE_BUFFER_H__

#include <stdbool.h>
#include <stdlib.h>

#include "core/types.h"

typedef struct {
  size_t len;
  size_t cap;
  byte_t* data;
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
 */
void byte_buf2str(byte_buf_t* buf);

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
byte_buf_t* byte_buf2hex_string(byte_buf_t* buf);

#ifdef __cplusplus
}
#endif

#endif
