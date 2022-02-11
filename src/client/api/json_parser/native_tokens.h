// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_NATIVE_TOKENS_H__
#define __CLIENT_API_JSON_PARSER_NATIVE_TOKENS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/native_tokens.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to native tokens object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] native_tokens Transaction Native Tokens object
 * @return int 0 on success
 */
int json_native_tokens_deserialize(cJSON *output_obj, native_tokens_t **native_tokens);

// TODO
cJSON *json_native_tokens_serialize(native_tokens_t **native_tokens);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_NATIVE_TOKENS_H__
