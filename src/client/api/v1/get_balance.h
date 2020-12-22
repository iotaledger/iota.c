// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_BALANCE_H__
#define __CLIENT_API_V1_BALANCE_H__

#include <stdint.h>

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/types.h"

typedef struct {
  uint16_t max_results;
  uint16_t count;
  uint64_t balance;
  char address[IOTA_ADDRESS_HEX_BYTES + 1];  // with null terminator
} get_balance_t;

typedef struct {
  bool is_error;
  union {
    res_err_t *error;
    get_balance_t *output_balance;
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
 * @brief Gets balance from address
 *
 * @param[in] ctx IOTA Client conf
 * @param[in] addr The address
 * @param[out] res A response object of balance info
 * @return int 0 on success
 */
int get_balance(iota_client_conf_t const *ctx, char *addr, res_balance_t *res);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_V1_BALANCE_H__
