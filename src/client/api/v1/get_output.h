// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
#ifndef __CLIENT_API_V1_OUTPUT_H__
#define __CLIENT_API_V1_OUTPUT_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "client/network/http.h"

#define IOTA_OUTPUT_ID_HEX_BYTES 68

/**
 * @brief The output object of get_output
 *
 */
typedef struct {
  char msg_id[64];
  char tx_id[64];
  char addr[64];
  uint32_t output_type;
  uint32_t address_type;
  uint64_t amount;
  uint16_t output_idx;
  bool is_spent;
} get_output_t;

/**
 * @brief The response object of get_output
 *
 */
typedef struct {
  bool is_error;
  union {
    res_err_t *error;
    get_output_t output;
  } u;
} res_output_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get an output from a given output ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] output_id A hex string of the output ID
 * @param[out] res The response object from node
 * @return int 0 on success
 */
int get_output(iota_client_conf_t const *conf, char const output_id[], res_output_t *res);

/**
 * @brief The JSON deserialization of the get output response
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res The output of deserialized response
 * @return int 0 on success
 */
int deser_get_output(char const *const j_str, res_output_t *res);

#ifdef __cplusplus
}
#endif

#endif
