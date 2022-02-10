// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_UNLOCK_BLOCKS_H__
#define __CLIENT_API_JSON_PARSER_UNLOCK_BLOCKS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/unlock_block.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to unlock blocks list object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] unlock_blocks Unlock blocks object
 * @return int 0 on success
 */
int json_unlock_blocks_deserialize(cJSON* blocks_obj, unlock_list_t** unlock_blocks);

// TODO
cJSON* json_unlock_blocks_serialize(unlock_list_t* blocks);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_UNLOCK_BLOCKS_H__
