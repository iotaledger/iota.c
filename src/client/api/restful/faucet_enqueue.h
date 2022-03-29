// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_FAUCET_ENQUEUE_H__
#define __CLIENT_FAUCET_ENQUEUE_H__

#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/utils/macros.h"

/**
 * @brief Store address and waiting requests count returned in response of faucet enqueue request
 *
 */
typedef struct {
  char bech32_address[BIN_TO_HEX_STR_BYTES(ED25519_PUBKEY_BYTES)];  ///< The bech32 encoded address that is
                                                                    ///< returned in response
  uint32_t waiting_reqs_count;                                      ///< The number of requests in faucet queue
} faucet_enqueue_t;

/**
 * @brief The response of faucet enqueue request
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;          ///< Error message if is_error is True
    faucet_enqueue_t req_res;  ///< Faucet enqueue response if is_error is False
  } u;
} res_faucet_enqueue_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Faucet enqueue response JSON deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object
 * @return int 0 on success
 */
int deser_faucet_enqueue_response(char const *const j_str, res_faucet_enqueue_t *res);

/**
 * @brief Request tokens to address from faucet
 * @param[in] conf The client endpoint configuration
 * @param[in] addr_bech32 The bech32 address to which the tokens needs to be requested from faucet
 * @param[out] res The faucet enqueue response object
 *
 * @return res_faucet_enqueue_t*
 */
int req_tokens_to_addr_from_faucet(iota_client_conf_t const *conf, char const addr_bech32[], res_faucet_enqueue_t *res);

#ifdef __cplusplus
}
#endif

#endif
