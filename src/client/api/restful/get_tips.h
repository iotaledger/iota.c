// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_TIPS_H__
#define __CLIENT_API_RESTFUL_TIPS_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "client/network/http.h"
#include "utarray.h"

typedef UT_array get_tips_t;

/**
 * @brief The response of get tips
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;  ///< Error message if is_error is True
    get_tips_t *tips;  ///< list of tips if is_error is False
  } u;
} res_tips_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a res_tips_t response object
 *
 * @return res_tips_t*
 */
res_tips_t *res_tips_new();

/**
 * @brief Free a res_tips_t response object
 *
 * @param[in] tips a response object
 */
void res_tips_free(res_tips_t *tips);

/**
 * @brief Gets tips for attaching to a message
 *
 * Returns tips that are ideal for attaching to a message. The tips can be considered as `non-lazy` and are therefore
 * ideal for attaching a message.
 *
 * @param[in] conf The client endpoint configuration
 * @param[out] res A response object of tips object
 * @return int 0 on success
 */
int get_tips(iota_client_conf_t const *conf, res_tips_t *res);

/**
 * @brief Tips response deserialization
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res A response object of tips object
 * @return int 0 on success
 */
int get_tips_deserialize(char const *const j_str, res_tips_t *res);

/**
 * @brief Gets the number of message IDs
 *
 * @param[in] tips A response object
 * @return size_t
 */
size_t get_tips_id_count(res_tips_t *tips);

/**
 * @brief Gets a message ID by a given index
 *
 * @param[in] tips A response object
 * @param[in] index A index of a message ID
 * @return char*
 */
char *get_tips_id(res_tips_t *tips, size_t index);

#ifdef __cplusplus
}
#endif

#endif
