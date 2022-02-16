// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_PAYLOADS_H__
#define __CLIENT_API_JSON_PARSER_PAYLOADS_H__

#include "cJSON.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON payload to transaction payload object
 *
 * @param[in] payload A payload JSON object
 * @param[out] tx A transaction payload object
 * @return int 0 on success
 */
int json_transaction_deserialize(cJSON* payload, transaction_payload_t* tx);

/**
 * @brief Serialize a transaction payload object to JSON object
 *
 * @param[in] tx A transaction payload object
 * @return cJSON* NULL on errors
 */
cJSON* json_transaction_serialize(transaction_payload_t* tx);

/**
 * @brief Deserialize JSON payload to milestone payload object
 *
 * @param[in] payload A payload JSON object
 * @param[out] ms A milestone payload object
 * @return int 0 on success
 */
int milestone_deserialize(cJSON* payload, milestone_t* ms);

/**
 * @brief Deserialize JSON data to tagged data object
 *
 * @param[in] payload A payload JSON object
 * @param[out] tagged_data A tagged data object
 * @return int 0 on success
 */
int json_tagged_deserialize(cJSON* payload, tagged_data_t** tagged_data);

/**
 * @brief Serialize a tagged data payload object to JSON object
 *
 * @param[in] tagged_data A tagged data object
 * @return cJSON* NULL on errors
 */
cJSON* json_tagged_serialize(tagged_data_t* tagged_data);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_PAYLOADS_H__
