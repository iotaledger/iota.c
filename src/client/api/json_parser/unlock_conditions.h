// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_UNLOCK_CONDITIONS_H__
#define __CLIENT_API_JSON_PARSER_UNLOCK_CONDITIONS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/unlock_conditions.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON address unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] blk_list Unlock conditions list object
 * @return int 0 on success
 */
int json_cond_blk_addr_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list);

/**
 * @brief Deserialize JSON dust deposit return unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] blk_list Unlock conditions list object
 * @return int 0 on success
 */
int json_cond_blk_dust_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list);

/**
 * @brief Deserialize JSON timelock unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] blk_list Unlock conditions list object
 * @return int 0 on success
 */
int json_cond_blk_timelock_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list);

/**
 * @brief Deserialize JSON expiration unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] blk_list Unlock conditions list object
 * @return int 0 on success
 */
int json_cond_blk_expir_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list);

/**
 * @brief Deserialize JSON state controller address unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] blk_list Unlock conditions list object
 * @return int 0 on success
 */
int json_cond_blk_state_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list);

/**
 * @brief Deserialize JSON governor address unlock condition to unlock condition object
 *
 * @param[in] unlock_cond_obj Unlock conditions JSON object
 * @param[out] blk_list Unlock conditions list object
 * @return int 0 on success
 */
int json_cond_blk_governor_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list);

/**
 * @brief Deserialize JSON unlock conditions list to unlock conditions list object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] blk_list Unlock conditions list object
 * @return int 0 on success
 */
int json_cond_blk_list_deserialize(cJSON *output_obj, cond_blk_list_t *blk_list);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_UNLOCK_CONDITIONS_H__
