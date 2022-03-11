// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_INPUTS_INPUTS_H__
#define __CLIENT_API_JSON_PARSER_INPUTS_INPUTS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to an utxo input list object
 *
 * @param[in] inputs_obj inputs JSON object
 * @param[out] inputs An utxo input list
 * @return int 0 on success
 */
int json_inputs_deserialize(cJSON* inputs_obj, utxo_inputs_list_t** inputs);

/**
 * @brief Serialize input list to JSON object
 *
 * @param[in] inputs An input list object
 * @return cJSON* NULL on errors
 */
cJSON* json_inputs_serialize(utxo_inputs_list_t* inputs);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_INPUTS_INPUTS_H__
