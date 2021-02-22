// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_BALANCE_H__
#define __CLIENT_API_V1_BALANCE_H__

#include <stdint.h>

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/types.h"

/**
 * @brief Stores address string and amount of balance
 *
 */
typedef struct {
  uint8_t address_type;                  ///< 0 = ED25519 address
  uint64_t balance;                      ///< amount of balance
  char address[IOTA_ADDRESS_HEX_BYTES];  ///< hex address string, ex:
                                         ///< 7ED3D67FC7B619E72E588F51FEF2379E43E6E9A856635843B3F29AA3A3F1F006
} get_balance_t;

/**
 * @brief The response of get balance API call
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;               ///< Error message if is_error is True
    get_balance_t *output_balance;  ///< a balance object if is_error is False
  } u;
} res_balance_t;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Allocates balance response object
 * @return res_balance_t*
 */
res_balance_t *res_balance_new();

/**
 * @brief Frees an balance response object
 * @param[in] res A response object
 */
void res_balance_free(res_balance_t *res);

/**
 * @brief balance info JSON deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object of balance info
 * @return int 0 on success
 */
int deser_balance_info(char const *const j_str, res_balance_t *res);

/**
 * @brief Gets balance from an address
 *
 * @param[in] ctx IOTA Client conf
 * @param[in] addr The address
 * @param[out] res A response object of balance info
 * @return int 0 on success
 */
int get_balance(iota_client_conf_t const *ctx, char const addr[], res_balance_t *res);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_V1_BALANCE_H__
