// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_COMMON_H__
#define __CLIENT_API_JSON_PARSER_COMMON_H__

#include "client/api/json_parser/json_utils.h"
#include "core/address.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON address data to address object
 *
 * @param[in] json_obj JSON object
 * @param[in] json_address_key JSON key for address
 * @param[out] address Deserialized address
 * @return int 0 on success
 */
int json_parser_common_address_deserialize(cJSON *json_obj, char const *const json_address_key, address_t *address);

/**
 * @brief Serialize An address to JSON object
 *
 * @param[in] address An address object
 * @return cJSON* NULL on error
 */
cJSON *json_parser_common_address_serialize(address_t *address);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_COMMON_H__
