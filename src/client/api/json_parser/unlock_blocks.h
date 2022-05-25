// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_UNLOCKS_H__
#define __CLIENT_API_JSON_PARSER_UNLOCKS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/unlock_block.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to an unlock list object
 *
 * @param[in] unlocks_obj Unlocks JSON object
 * @param[out] unlock_list Unlocks object
 * @return int 0 on success
 */
int json_unlocks_deserialize(cJSON* unlocks_obj, unlock_list_t** unlock_list);

/**
 * @brief Serialize an unlock list to a JSON object
 *
 * @param[in] unlock_list An unlock list
 * @return cJSON* NULL on errors
 */
cJSON* json_unlocks_serialize(unlock_list_t* unlock_list);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_UNLOCKS_H__
