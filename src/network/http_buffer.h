#ifndef __NETWORK_HTTP_BUFFER_H__
#define __NETWORK_HTTP_BUFFER_H__

#include <stdbool.h>
#include <stdlib.h>

// #include "models/types.h"
// TODO: use byte_t in models/types.h
#include <stdint.h>
typedef uint8_t byte_t;

typedef struct {
  size_t len;
  byte_t* data;
} http_buf_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates data buffer
 *
 * @return http_buf_t*
 */
http_buf_t* http_buf_new();

/**
 * @brief Allocates data buffer with given data
 *
 * @param[in] data Inital data
 * @param[in] len The size of data
 * @return http_buf_t*
 */
http_buf_t* http_buf_new_with_data(byte_t data[], size_t len);

/**
 * @brief Appends data to buffer
 *
 * @param[in] buf A buffer object
 * @param[in] data The data for appending
 * @param[in] len The size of data
 * @return true
 * @return false
 */
bool http_buf_append(http_buf_t* buf, byte_t data[], size_t len);

/**
 * @brief Frees data buffer
 *
 * @param[in] buf
 */
void http_buf_free(http_buf_t* buf);

/**
 * @brief Converts data of http buffer to string
 *
 * In general, the data from http response is binary data,
 * we append the null terminator to it and treat it as a string.
 *
 * @param buf
 */
void http_buf2str(http_buf_t* buf);

#ifdef __cplusplus
}
#endif

#endif
