// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_TRANSACTION_INCLUDED_MESSAGE_H__
#define __CLIENT_API_RESTFUL_TRANSACTION_INCLUDED_MESSAGE_H__

#include "client/api/restful/get_message.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get included block data from a given transaction ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] tx_id A transaction ID to query
 * @param[out] res The block body of the given ID
 * @return int 0 on success
 */
int get_transaction_included_block_by_id(iota_client_conf_t const *conf, char const tx_id[], res_block_t *res);

/**
 * @brief The block response deserialization
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res the block object
 * @return int 0 on success
 */
int deser_get_transaction_included_block(char const *const j_str, res_block_t *res);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_V1_TRANSACTION_INCLUDED_MESSAGE_H__
