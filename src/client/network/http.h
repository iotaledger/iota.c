// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_NETWORK_HTTP_H__
#define __CLIENT_NETWORK_HTTP_H__

/**
 * @brief Abstract layer of http client for IOTA client
 *
 */

#include <stdbool.h>
#include <stdlib.h>

#include "core/utils/byte_buffer.h"

typedef struct {
  char const* url;       ///< HTTP URL, it overrides fields below, if any
  char const* host;      ///< Domain name or IP as string
  char const* path;      ///< HTTP path
  char const* query;     ///< HTTP query
  char const* cert_pem;  ///< SSL certification in PEM format
  uint16_t port;         ///< port to connect
  bool use_tls;          ///< Use TLS or not
} http_client_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Inits http client instance
 *
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
 * @param[in] url The server url
 * @param[in] request The request of body
 * @param[out] response The response data
 * @param[out] status HTTP status code
 * @return int 0 on success
 */
int http_client_post(http_client_config_t const* const config, byte_buf_t const* const request,
                     byte_buf_t* const response, long* status);

/**
 * @brief Performs http GET
 *
 * @param[in] url The server url
 * @param[out] response The response data
 * @param[out] status HTTP status code
 * @return int 0 on success
 */
int http_client_get(http_client_config_t const* const config, byte_buf_t* const response, long* status);

#ifdef __cplusplus
}
#endif

#endif
