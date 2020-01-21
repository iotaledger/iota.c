/*
 * Copyright (c) 2018 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

/**
 * @ingroup cclient
 *
 * @{
 *
 * @file
 * @brief
 *
 */
#ifndef CCLIENT_SERVICE_H_
#define CCLIENT_SERVICE_H_

#include <stdlib.h>

#include "cclient/serialization/json/logger.h"
#include "cclient/serialization/serializer.h"
#include "common/errors.h"
#include "utils/logger_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOST_MAX_ELN 256
#define CONTENT_TYPE_MAX_ELN 128

/**
 * @brief HTTP request information
 *
 */
typedef struct {
  char host[HOST_MAX_ELN];                 /**< Host name */
  char content_type[CONTENT_TYPE_MAX_ELN]; /**< Content type of request */
  char accept[CONTENT_TYPE_MAX_ELN];       /**< Accept content type of response */
  char path[CONTENT_TYPE_MAX_ELN];         /**< the request path is "/" for an iota client library */
  uint16_t port;                           /**< Port number of the host*/
  int api_version;                         /**< Number of IOTA API version */
  char const* ca_pem;                      /**< String of root ca */
} http_info_t;

/**
 * @brief client service
 *
 */
typedef struct {
  http_info_t http;                  /**< The http request information */
  serializer_t serializer;           /**< The client serializer */
  serializer_type_t serializer_type; /** The type of serialization */
} iota_client_service_t;

/**
 * @brief init CClient service
 *
 * @param serv service object
 * @return error code
 */
retcode_t iota_client_service_init(iota_client_service_t* const serv);

#ifdef __cplusplus
}
#endif

#endif  // CCLIENT_SERVICE_H_

/** @} */