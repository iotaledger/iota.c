/*
 * Copyright (c) 2018 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

#ifndef __CCLIENT_HTTP_SOCKETS_H__
#define __CCLIENT_HTTP_SOCKETS_H__

#include <stdbool.h>

#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "common/errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief mbedtls context
 *
 */
typedef struct mbedtls_ctx_s {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config ssl_conf;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt client_cacert;
  mbedtls_pk_context pk_ctx;
  mbedtls_net_context net_ctx;
  bool enable_tls;
} mbedtls_ctx_t;

/**
 * @brief create mbedtls network socket
 *
 * @param tls_ctx[in] mbedtls context
 * @param host[in] host address or IP
 * @param port[in] host port number
 * @param ca_pem[in] Certificate Authority in pem format
 * @param client_cert_pem[in] client certificate
 * @param client_pk_pem[in] client private key
 * @param error[out] the error code
 * @return int socket file descriptor
 */
int mbedtls_socket_connect(mbedtls_ctx_t *tls_ctx, char const *host, uint16_t port, char const *ca_pem,
                           char const *client_cert_pem, char const *client_pk_pem, retcode_t *error);
/**
 * @brief socket send implementation
 *
 * @param ctx[in] mbedtls context
 * @param data[in] a buffer holding the data
 * @param size[in] number of bytes should be sent
 * @return int the number of bytes actually written
 */
int mbedtls_socket_send(mbedtls_ctx_t *ctx, char const *data, size_t size);

/**
 * @brief socket receive impelmentation
 *
 * @param ctx[in] mbedtls context
 * @param data[in] data buffer
 * @param size[in] max number of bytes to read
 * @return int the number of bytes read.
 */
int mbedtls_socket_recv(mbedtls_ctx_t *ctx, char *data, size_t size);

/**
 * @brief clean up mbedtls socket
 *
 * @param tls_ctx[in] mbedtls context
 */
void mbedtls_socket_close(mbedtls_ctx_t *tls_ctx);

#ifdef __cplusplus
}
#endif

#endif  // __CCLIENT_HTTP_SOCKETS_H__
