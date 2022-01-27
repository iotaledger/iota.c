// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_MODELS_JSON_PARSER_COMMON_H__
#define __CLIENT_API_RESTFUL_MODELS_JSON_PARSER_COMMON_H__

#include "client/api/json_utils.h"
#include "core/address.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Deserialize JSON address data to address object
 *
 * @param[in] json_obj JSON object
 * @param[out] address Deserialized address
 * @return int 0 on success
 */
int json_parser_common_address_deserialize(cJSON *json_obj, address_t *address);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_RESTFUL_MODELS_JSON_PARSER_COMMON_H__
