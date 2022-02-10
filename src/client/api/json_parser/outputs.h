// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUTS_H__
#define __CLIENT_API_JSON_PARSER_OUTPUTS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/outputs.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to outputs list object
 *
 * @param[in] outputs_obj An outputs JSON object
 * @param[out] outputs An output list object
 * @return int 0 on success
 */
int json_outputs_deserialize(cJSON *outputs_obj, utxo_outputs_list_t **outputs);

// TODO
cJSON *json_outputs_serialize(utxo_outputs_list_t *outputs);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUTS_H__
