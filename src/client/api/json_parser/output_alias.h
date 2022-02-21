// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUT_ALIAS_H__
#define __CLIENT_API_JSON_PARSER_OUTPUT_ALIAS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/output_alias.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to output alias object
 *
 * @param[in] output_obj An output JSON object
 * @param[out] alias A new alias object
 * @return int 0 on success
 */
int json_output_alias_deserialize(cJSON *output_obj, output_alias_t **alias);

/**
 * @brief Serialize Alias output to JSON object
 *
 * @param[in] alias An alias output object
 * @return cJSON* NULL on errors
 */
cJSON *json_output_alias_serialize(output_alias_t *alias);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUT_ALIAS_H__
