// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_TIPS_H__
#define __CLIENT_API_V1_TIPS_H__

#include <stdbool.h>
#include <stdint.h>

#include "utarray.h"

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "client/network/http.h"

#define STR_TIP_MSG_ID_LEN 64  // the length of message id string

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
 * @brief Gets tips
 *
 * Returns two non-lazy tips. In case the node can only provide one tip, tip1 and tip2 are identical.
 *
 * @param[in] conf The client endpoint configuration
 * @param[out] res A response object of tips object
 * @return int 0 on success
 */
int get_tips(iota_client_conf_t const *conf, res_tips_t *res);

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

/**
 * @brief tips response deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object of tips object
 * @return int 0 on success
 */
int deser_get_tips(char const *const j_str, res_tips_t *res);

/**
 * @brief Allocate a get_tips response object
 *
 * @return res_tips_t*
 */
res_tips_t *res_tips_new();

/**
 * @brief Free a get_tips response object
 *
 * @param tips a response object
 */
void res_tips_free(res_tips_t *tips);

#ifdef __cplusplus
}
#endif

#endif
