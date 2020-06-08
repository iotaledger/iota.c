/*
 * Copyright (c) 2018 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

/**
 * @ingroup cclient_http
 *
 * @{
 *
 * @file
 * @brief
 *
 */
#ifndef CCLIENT_HTTP_HTTP_H_
#define CCLIENT_HTTP_HTTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "cclient/service.h"

// socket buffer can overwrite through the preprocessor macro.
#ifndef CCLIENT_HTTP_BUFFER_SIZE
#ifdef __XTENSA__
#define CCLIENT_HTTP_BUFFER_SIZE 2 * 1024
#else
/**
 * @name The size of HTTP/HTTPS receive buffer
 * @{
 */
#define CCLIENT_HTTP_BUFFER_SIZE 4 * 1024
/** @} */
#endif
#endif

#define CCLIENT_SOCKET_RETRY 5

extern char const* khttp_ApplicationJson;
extern char const* khttp_ApplicationFormUrlencoded;

/**
 * @brief HTTP/HTTPS Client implementation
 *
 * @param service_opaque an opaque object
 * @param req_data http data to send
 * @param res_data the response from server
 * @return An error code
 */
retcode_t iota_service_query(void const* const service_opaque, char_buffer_t const* const req_data,
                             char_buffer_t* res_data);

#ifdef __cplusplus
}
#endif

#endif  // CCLIENT_HTTP_HTTP_H_

/** @} */