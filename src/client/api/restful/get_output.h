// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_OUTPUT_H__
#define __CLIENT_API_RESTFUL_OUTPUT_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "client/network/http.h"
#include "core/models/inputs/utxo_input.h"
#include "core/models/message.h"
#include "core/models/outputs/outputs.h"

/**
 * @brief An output response object
 *
 */
typedef struct {
  byte_t msg_id[IOTA_MESSAGE_ID_BYTES];           ///< the message IDs that references the output
  byte_t tx_id[IOTA_TRANSACTION_ID_BYTES];        ///< The transaction ID of this output
  uint16_t output_index;                          ///< the index of this output
  bool is_spent;                                  ///< is spent or not
  uint32_t ml_index_spent;                        ///< milestone index spent (present only if is_spent is true)
  uint32_t ml_time_spent;                         ///< milestone timestamp spent (present only if is_spent is true)
  byte_t tx_id_spent[IOTA_TRANSACTION_ID_BYTES];  ///< The transaction ID of spent (present only if is_spent is true)
  uint32_t ml_index_booked;                       ///< milestone index booked
  uint32_t ml_time_booked;                        ///< milestone timestamp booked
  uint32_t ledger_index;                          ///< ledger index
  utxo_output_t *output;                          ///< an output object
} get_output_t;

/**
 * @brief The response object of get_output
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;    ///< Error message if is_error is True
    get_output_t *data;  ///< an output object if is_error is False
  } u;
} res_output_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create an output object
 *
 * @return get_output_t*
 */
get_output_t *get_output_new();

/**
 * @brief Free an output object
 *
 * @param[in] res An output object
 */
void get_output_free(get_output_t *res);

/**
 * @brief Create an output response object
 *
 * @return res_output_t*
 */
res_output_t *get_output_response_new();

/**
 * @brief Free an output response object
 *
 * @param[in] res An output response
 */
void get_output_response_free(res_output_t *res);

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
 * @brief Parse an output response JSON Object
 *
 * @param[in] j_str A string of the JSON response object
 * @param[out] res The output of parsed object
 * @return int 0 on success
 */
int parse_get_output(char const *const j_str, get_output_t *res);

/**
 * @brief The JSON deserialization of the get output response
 *
 * @param[in] j_str A string of the JSON object
 * @param[out] res The output of deserialized response
 * @return int 0 on success
 */
int deser_get_output(char const *const j_str, res_output_t *res);

/**
 * @brief Print get output object
 *
 * @param[in] res A get output object
 * @param[in] indentation Tab indentation when printing output response
 */
void print_get_output(get_output_t *res, uint8_t indentation);

/**
 * @brief Print out an output response object
 *
 * @param[in] res An output response
 * @param[in] indentation Tab indentation when printing output response
 */
void dump_get_output_response(res_output_t *res, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
