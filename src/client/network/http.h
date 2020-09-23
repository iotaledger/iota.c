#ifndef __CLIENT_NETWORK_HTTP_H__
#define __CLIENT_NETWORK_HTTP_H__

/**
 * @brief Abstract layer of http client for IOTA client
 *
 */

#include <stdbool.h>
#include <stdlib.h>

#include "client/network/http_buffer.h"

typedef struct {
  char* url;
  char* host;
  char* path;
  char* query;
  char* username;
  char* password;
  char const* cert_pem;
  int port;
} http_client_config_t;

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
void http_client_post(http_buf_t* const response, http_client_config_t const* const config,
                      http_buf_t const* const request);

/**
 * @brief Performs http GET
 *
 * @param[out] response The response data
 * @param[in] url The server url
 */
void http_client_get(http_buf_t* const response, http_client_config_t const* const config);

#ifdef __cplusplus
}
#endif

#endif
