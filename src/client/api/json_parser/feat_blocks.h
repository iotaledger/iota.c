// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_FEAT_BLOCKS_H__
#define __CLIENT_API_JSON_PARSER_FEAT_BLOCKS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/feat_blocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON sender feature block to feature block object
 *
 * @param[in] feat_block_obj Feature block JSON object
 * @param[out] feat_blocks Feature blocks list object
 * @return int 0 on success
 */
int json_feat_blk_sender_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks);

/**
 * @brief Deserialize JSON issuer feature block to feature block object
 *
 * @param[in] feat_block_obj Feature block JSON object
 * @param[out] feat_blocks Feature blocks list object
 * @return int 0 on success
 */
int json_feat_blk_issuer_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks);

/**
 * @brief Deserialize JSON metadata feature block to feature block object
 *
 * @param[in] feat_block_obj Feature block JSON object
 * @param[out] feat_blocks Feature blocks list object
 * @return int 0 on success
 */
int json_feat_blk_metadata_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks);

/**
 * @brief Deserialize JSON tag feature block to feature block object
 *
 * @param[in] feat_block_obj Feature block JSON object
 * @param[out] feat_blocks Feature blocks list object
 * @return int 0 on success
 */
int json_feat_blk_tag_deserialize(cJSON *feat_block_obj, feat_blk_list_t *feat_blocks);

/**
 * @brief Deserialize JSON data to feature blocks list object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] feat_blocks Feature blocks list object
 * @return int 0 on success
 */
int json_feat_blocks_deserialize(cJSON *output_obj, feat_blk_list_t *feat_blocks);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_FEAT_BLOCKS_H__
