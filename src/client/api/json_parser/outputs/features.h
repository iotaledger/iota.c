// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUTS_FEATURES_H__
#define __CLIENT_API_JSON_PARSER_OUTPUTS_FEATURES_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/features.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON sender feature to feature object
 *
 * @param[in] feat_obj Feature JSON object
 * @param[out] feat_list Features list object
 * @return int 0 on success
 */
int json_feat_sender_deserialize(cJSON *feat_obj, feature_list_t **feat_list);

/**
 * @brief Deserialize JSON issuer feature to feature object
 *
 * @param[in] feat_obj Feature JSON object
 * @param[out] feat_list Features list object
 * @return int 0 on success
 */
int json_feat_issuer_deserialize(cJSON *feat_obj, feature_list_t **feat_list);

/**
 * @brief Deserialize JSON metadata feature to feature object
 *
 * @param[in] feat_obj Feature JSON object
 * @param[out] feat_list Features list object
 * @return int 0 on success
 */
int json_feat_metadata_deserialize(cJSON *feat_obj, feature_list_t **feat_list);

/**
 * @brief Deserialize JSON tag feature to feature object
 *
 * @param[in] feat_obj Feature JSON object
 * @param[out] feat_list Features list object
 * @return int 0 on success
 */
int json_feat_tag_deserialize(cJSON *feat_obj, feature_list_t **feat_list);

/**
 * @brief Deserialize JSON data to features list object
 *
 * @param[in] output_obj Output JSON object
 * @param[in] immutable Flag which indicates if feature is immutable
 * @param[out] feat_list Features list object
 * @return int 0 on success
 */
int json_features_deserialize(cJSON *output_obj, bool immutable, feature_list_t **feat_list);

/**
 * @brief Serialize a feature list
 *
 * @param[in] feat_list A feature list
 * @return cJSON* NULL on errors
 */
cJSON *json_features_serialize(feature_list_t *feat_list);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUTS_FEAT_BLOCKS_H__
