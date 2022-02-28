// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_FAUCET_ENQUE_H__
#define __CLIENT_FAUCET_ENQUE_H__

#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/address.h"

/**
 * @brief Store address and waiting requests count returned in response of faucet enque request
 *
 */
typedef struct {
  char bech32_address[BECH32_ENCODED_ED25519_ADDRESS_STR_LEN + 1];  ///< The bech32 encoded address that is returned
                                                                    ///< in response
  uint64_t waiting_reqs_count;                                      ///< The number of requests in faucet queue
} req_faucet_tokens_t;

/**
 * @brief The response of faucet enque request
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;             ///< Error message if is_error is True
    req_faucet_tokens_t req_res;  ///< Faucet enque response if is_error is False
  } u;
} res_req_faucet_tokens_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Faucet enque response JSON deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object
 * @return int 0 on success
 */
int deser_faucet_enque_response(char const *const j_str, res_req_faucet_tokens_t *res);

/**
 * @brief Request tokens to address from faucet
 * @param[in] conf The client endpoint configuration
 * @param[in] addr_bech32 The bech32 address to which the tokens needs to be requested from faucet
 *
 * @return res_req_faucet_tokens_t*
 */
int req_tokens_to_addr_from_faucet(iota_client_conf_t const *conf, char const addr_bech32[],
                                   res_req_faucet_tokens_t *res);

#ifdef __cplusplus
}
#endif

#endif