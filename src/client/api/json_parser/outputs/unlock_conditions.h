// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUTS_UNLOCK_CONDITIONS_H__
#define __CLIENT_API_JSON_PARSER_OUTPUTS_UNLOCK_CONDITIONS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/unlock_conditions.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON address unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_addr_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Deserialize JSON storage deposit return unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_storage_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Deserialize JSON timelock unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_timelock_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Deserialize JSON expiration unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_expir_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Deserialize JSON state controller address unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_state_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Deserialize JSON governor address unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_governor_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Deserialize JSON immutable alias address unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_immut_alias_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Deserialize JSON unlock conditions list to unlock conditions list object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] cond_list Unlock conditions list object
 * @return int 0 on success
 */
int json_condition_list_deserialize(cJSON *output_obj, unlock_cond_list_t **cond_list);

/**
 * @brief Serialize unlock conditions
 *
 * @param[in] cond_list An unlock conditions object
 * @return cJSON* NULL on errors
 */
cJSON *json_condition_list_serialize(unlock_cond_list_t *cond_list);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUTS_UNLOCK_CONDITIONS_H__
