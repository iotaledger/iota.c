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
 * @brief An output object
 *
 */
typedef struct {
  char msg_id[64];        ///< the message IDs that references the output
  char tx_id[64];         ///< the transaction ID
  char addr[64];          ///< the address in hex string
  uint32_t output_type;   ///< the output type
  uint32_t address_type;  ///< the address type
  uint64_t amount;        ///< the amount of this output
  uint16_t output_idx;    ///< the index of this output
  bool is_spent;          ///< is spent or not
} get_output_t;

/**
 * @brief The response object of get_output
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;     ///< Error message if is_error is True
    get_output_t output;  ///< an output object if is_error is False
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

/**
 * @brief Print out an output response object
 *
 * @param[in] res An output response
 */
void dump_output_response(res_output_t *res);

#ifdef __cplusplus
}
#endif

#endif
