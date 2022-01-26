// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_MODELS_INPUTS_JSON_UTXO_INPUT_H__
#define __CLIENT_API_RESTFUL_MODELS_INPUTS_JSON_UTXO_INPUT_H__

#include "client/api/json_utils.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to an utxo input list object
 *
 * @param[in] essence_obj Essence JSON object
 * @param[out] essence Transaction essence data object
 * @return int 0 on success
 */
int json_inputs_deserialize(cJSON *essence_obj, transaction_essence_t *essence);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_RESTFUL_MODELS_INPUTS_JSON_UTXO_INPUT_H__
