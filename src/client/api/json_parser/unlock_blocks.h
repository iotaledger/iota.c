// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_UNLOCK_BLOCKS_H__
#define __CLIENT_API_JSON_PARSER_UNLOCK_BLOCKS_H__

#include "client/api/json_parser/json_utils.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON data to unlock blocks list object
 *
 * @param[in] output_obj Output JSON object
 * @param[out] transaction_payload_t Transaction payload object
 * @return int 0 on success
 */
int json_unlock_blocks_deserialize(cJSON *blocks_obj, transaction_payload_t *payload_tx);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_UNLOCK_BLOCKS_H__
