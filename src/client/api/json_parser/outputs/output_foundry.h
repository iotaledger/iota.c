// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_FOUNDRY_H__
#define __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_FOUNDRY_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/output_foundry.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize a JSON token scheme object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] token_scheme A token scheme object
 * @return int 0 on success
 */
int json_token_scheme_deserialize(cJSON *output_obj, token_scheme_t **token_scheme);

/**
 * @brief Serialize token scheme
 *
 * @param[in] scheme A token scheme object
 * @return cJSON* NULL on errors
 */
cJSON *json_token_scheme_serialize(token_scheme_t *scheme);

/**
 * @brief Deserialize JSON data to output foundry object
 *
 * @param[in] output_obj An output JSON object
 * @param[out] foundry A new foundry object
 * @return int 0 on success
 */
int json_output_foundry_deserialize(cJSON *output_obj, output_foundry_t **foundry);

/**
 * @brief Serialize a foundry output to a JSON object
 *
 * @param[in] foundry A foundry output
 * @return cJSON* NULL on errors
 */
cJSON *json_output_foundry_serialize(output_foundry_t *foundry);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_FOUNDRY_H__
