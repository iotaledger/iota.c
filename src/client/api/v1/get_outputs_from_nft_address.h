// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_OUTPUTS_FROM_NFT_ADDRESS_H__
#define __CLIENT_API_V1_OUTPUTS_FROM_NFT_ADDRESS_H__

#include "utarray.h"

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/types.h"

/**
 * @brief An output NFT address object
 *
 */
typedef struct {
  uint32_t max_results;  ///< The number of results it can return at most.
  uint32_t count;        ///< The actual number of found results.
  UT_array *outputs;     ///< output IDs
  uint64_t ledger_idx;   ///< The ledger index at which the output was queried at.
} get_outputs_nft_address_t;

/**
 * @brief The response of get outputs from NFT address
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;                       ///< Error message if is_error is True
    get_outputs_nft_address_t *output_ids;  ///< an output object if is_error is False
  } u;
} res_outputs_nft_address_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates an output NFT address response object
 *
 * @return res_outputs_nft_address_t*
 */
res_outputs_nft_address_t *res_outputs_nft_address_new();

/**
 * @brief Frees an output NFT address response object
 *
 * @param[in] res A response object
 */
void res_outputs_nft_address_free(res_outputs_nft_address_t *res);

/**
 * @brief Gets a number of all outputs in outputs array
 *
 * @param[in] res A response object
 * @return size_t The length of output ids
 */
size_t res_outputs_nft_address_output_id_count(res_outputs_nft_address_t *res);

/**
 * @brief Gets an output id by given index
 *
 * @param[in] res A response object
 * @param[in] index The index of output id
 * @return char* A pointer to a string
 */
char *res_outputs_nft_address_output_id(res_outputs_nft_address_t *res, size_t index);

/**
 * @brief Outputs from NFT address deserialization
 *
 * @param[in] j_str A string of a JSON object
 * @param[out] res The response object
 * @return int 0 on successful
 */
int deserialize_outputs_from_nft_address(char const *const j_str, res_outputs_nft_address_t *res);

/**
 * @brief Gets output IDs from a given NFT address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] addr An NFT address in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_nft_address(iota_client_conf_t const *conf, char const addr[], res_outputs_nft_address_t *res);

#ifdef __cplusplus
}
#endif

#endif
