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

/**
 * @brief The utxo-changes object
 *
 */
typedef struct {
  uint32_t index;             ///< The index of the milestone
  UT_array *createdOutputs;   ///< The created outputs for the milestone
  UT_array *consumedOutputs;  ///< The consumed outputs of the milestone
} utxo_changes_t;

/**
 * @brief The response object for utxo-changes api
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;              ///< Error message if is_error is True
    utxo_changes_t *utxo_changes;  ///< A milestone object if is_error is False
  } u;
} res_utxo_changes_t;

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

/**
 * @brief Get milestone by a given index
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] index An index of the milestone to look up
 * @param[out] res The milestone response object
 * @return int 0 on success
 */
int get_milestone_by_index(iota_client_conf_t const *conf, uint32_t index, res_milestone_t *res);

/**
 * @brief Allocate a utxo-changes object
 *
 * @return utxo_changes_t*
 */
utxo_changes_t *utxo_changes_new();

/**
 * @brief Free a utxo-changes object
 *
 * @param[in] utxo_changes A utxo_changes_t* object
 */
void utxo_changes_free(utxo_changes_t *utxo_changes);

/**
 * @brief The utxo-output object deserialization
 *
 * @param[in] json_obj A response JSON object
 * @param[out] res A utxo-output object
 * @return int 0 on success
 */
int utxo_changes_deserialize(cJSON *json_obj, utxo_changes_t *res);

/**
 * @brief Allocate a utxo-changes response object
 *
 * @return res_utxo_changes_t*
 */
res_utxo_changes_t *res_utxo_changes_new();

/**
 * @brief Free a utxo-changes response object
 *
 * @param[in] res A res_utxo_changes_t* object
 */
void res_utxo_changes_free(res_utxo_changes_t *res);

/**
 * @brief The utxo-output response deserialization
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res A utxo-output response object for storing the response
 * @return int 0 on success
 */
int deser_get_utxo_changes(char const *const j_str, res_utxo_changes_t *res);

/**
 * @brief Get utxo-changes of a given milestone ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] ms_id A milestone ID to query
 * @param[out] res The utxo-changes response object
 * @return int 0 on success
 */
int get_utxo_changes_by_ms_id(iota_client_conf_t const *conf, char const ms_id[], res_utxo_changes_t *res);

/**
 * @brief Get  UTXO changes of a given milestone by milestone index.
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] index An index of the milestone to look up
 * @param[out] res The utxo-changes  response object
 * @return int 0 on success
 */
int get_utxo_changes_by_ms_index(iota_client_conf_t const *conf, uint32_t index, res_utxo_changes_t *res);

/**
 * @brief Print utxo-changes response object
 *
 * @param[in] res A utxo-changes response object
 * @param[in] indentation Tab indentation when printing output response
 */
void print_utxo_changes(res_utxo_changes_t *res, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
