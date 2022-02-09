// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_OUTPUT_EXTENDED_H__
#define __CLIENT_API_JSON_PARSER_OUTPUT_EXTENDED_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/outputs/output_extended.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to output extended object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] essence Transaction essence object
 * @return int 0 on success
 */
int json_output_extended_deserialize(cJSON* output_obj, transaction_essence_t* essence);

// TODO
cJSON* json_output_extended_serialize(output_extended_t* extended);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_OUTPUT_EXTENDED_H__
