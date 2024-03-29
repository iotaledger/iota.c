// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_NFT_H__
#define __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_NFT_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/output_nft.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to output NFT object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] nft A new NFT object
 * @return int 0 on success
 */
int json_output_nft_deserialize(cJSON *output_obj, output_nft_t **nft);

/**
 * @brief Serialize a NFT output to a JSON object
 *
 * @param[in] nft A NFT output
 * @return cJSON* NULL on errors
 */
cJSON *json_output_nft_serialize(output_nft_t *nft);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_NFT_H__
