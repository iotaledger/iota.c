// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_BASIC_H__
#define __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_BASIC_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/output_basic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to output basic object
 *
 * @param[in] output_obj An output JSON object
 * @param[out] basic A new basic object
 * @return int 0 on success
 */
int json_output_basic_deserialize(cJSON* output_obj, output_basic_t** basic);

/**
 * @brief Serialize basic output to JSON object
 *
 * @param basic An basic output
 * @return cJSON* NULL on errors
 */
cJSON* json_output_basic_serialize(output_basic_t* basic);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUTS_OUTPUT_BASIC_H__
