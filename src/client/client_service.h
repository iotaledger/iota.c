// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_SERVICE_H__
#define __CLIENT_SERVICE_H__

#include <stdint.h>
#include <stdlib.h>

#define IOTA_ENDPOINT_MAX_LEN 256

/**
 * @brief Client endpoint configuration
 *
 */
typedef struct {
  char url[IOTA_ENDPOINT_MAX_LEN];  ///< The URL string of the endpoint
  uint16_t port;                    ///< The port number of the endpoint
} iota_client_conf_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
