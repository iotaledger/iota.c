// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_SERVICE_H__
#define __CLIENT_SERVICE_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define IOTA_ENDPOINT_MAX_LEN 256

/**
 * @brief Client endpoint configuration
 *
 */
typedef struct {
  char host[IOTA_ENDPOINT_MAX_LEN];  ///< domain name or IP as string
  uint16_t port;                     ///< prot to connect
  bool use_tls;                      ///< Use TLS or not
} iota_client_conf_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
