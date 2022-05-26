// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_BLOCK_H__
#define __CLIENT_API_JSON_PARSER_BLOCK_H__

#include "cJSON.h"
#include "core/models/block.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize a JSON object to block
 *
 * @param[in] json_obj A JSON object
 * @param[out] blk The output block object
 * @return int 0 on success
 */
int json_block_deserialize(cJSON* json_obj, core_block_t* blk);

/**
 * @brief Serialize a block to JSON object
 *
 * @param[in] blk A block object
 * @return cJSON* NULL on errors
 */
cJSON* json_block_serialize(core_block_t* blk);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_BLOCK_H__
