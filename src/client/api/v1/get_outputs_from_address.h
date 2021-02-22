// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_OUTPUTS_FROM_ADDRESS_H__
#define __CLIENT_API_V1_OUTPUTS_FROM_ADDRESS_H__

#include "utarray.h"

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/types.h"

/**
 * @brief An output object
 *
 */
typedef struct {
  char address[IOTA_ADDRESS_HEX_BYTES + 1];  ///< hex-encoded string with null terminator.
  uint32_t max_results;                      ///< The number of results it can return at most.
  uint32_t count;                            ///< The actual number of found results.
  UT_array *outputs;                         ///< output IDs
} get_outputs_address_t;

/**
 * @brief The response of get outputs from address
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;                   ///< Error message if is_error is True
    get_outputs_address_t *output_ids;  ///< an output object if is_error is False
  } u;
} res_outputs_address_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocats an output address response object
 *
 * @return res_outputs_address_t*
 */
res_outputs_address_t *res_outputs_address_new();

/**
 * @brief Frees an output address response object
 *
 * @param[in] res A response object
 */
void res_outputs_address_free(res_outputs_address_t *res);

/**
 * @brief Gets an output id by given index
 *
 * @param[in] res A response object
 * @param[in] index The index of output id
 * @return char* A pointer to a string
 */
char *res_outputs_address_output_id(res_outputs_address_t *res, size_t index);

/**
 * @brief Gets the output id count
 *
 * @param[in] res A response object
 * @return size_t The length of output ids
 */
size_t res_outputs_address_output_id_count(res_outputs_address_t *res);

/**
 * @brief Outouts from address deserialization
 *
 * @param[in] j_str A string of a JSON object
 * @param[out] res The response object
 * @return int 0 on successful
 */
int deser_outputs_from_address(char const *const j_str, res_outputs_address_t *res);

/**
 * @brief Gets output IDs from a given address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] addr An address in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_address(iota_client_conf_t const *conf, char const addr[], res_outputs_address_t *res);

#ifdef __cplusplus
}
#endif

#endif