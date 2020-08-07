#ifndef __NETWORK_HTTP_H__
#define __NETWORK_HTTP_H__

#include <stdlib.h>

#include "network/http_buffer.h"

typedef void http_client_ctx;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Inits http client instance
 *
 * @param[out] ctx http instance context
 * @return true
 * @return false
 */
void http_client_init();

/**
 * @brief Clean up http client instance
 *
 */
void http_client_clean();

/**
 * @brief Performs http POST
 *
 * @param[out] response The response data
 * @param[in] url The server url
 * @param[in] request The request of body
 */
void http_client_post(http_buf_t* const response, char const* const url, http_buf_t const* const request);

/**
 * @brief Performs http GET
 *
 * @param[out] response The response data
 * @param[in] url The server url
 */
void http_client_get(http_buf_t* const response, char const* const url);

#ifdef __cplusplus
}
#endif

#endif
