// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_GET_MILESTONES_H__
#define __CLIENT_API_RESTFUL_GET_MILESTONES_H__

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/models/payloads/milestone.h"

/**
 * @brief The response of get milestones
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;         ///< Error message if is_error is True
    milestone_payload_t *ms;  ///< A milestone object if is_error is False
  } u;
} res_milestone_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a milestone response object
 *
 * @return res_milestone_t*
 */
res_milestone_t *res_milestone_new();

/**
 * @brief Free a milestone response object
 *
 * @param[in] res A milestone object
 */
void res_milestone_free(res_milestone_t *res);

/**
 * @brief The milestone response deserialization
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res the milestone object
 * @return int 0 on success
 */
int deser_get_milestone(char const *const j_str, res_milestone_t *res);

/**
 * @brief Get milestone from a given milestone ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] ms_id A milestone ID to query
 * @param[out] res The milestone response object
 * @return int 0 on success
 */
int get_milestone_by_id(iota_client_conf_t const *conf, char const ms_id[], res_milestone_t *res);

#ifdef __cplusplus
}
#endif

#endif
