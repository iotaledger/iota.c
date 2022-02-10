// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_OUTPUTS_ID_H__
#define __CLIENT_API_RESTFUL_OUTPUTS_ID_H__

#include "utarray.h"

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/types.h"

/**
 * @brief An output object
 *
 */
typedef struct {
  uint64_t ledger_idx;  ///< The ledger index at which the output was queried at.
  uint32_t page_size;   ///< The number of output id's returned in a single response.
  char *cursor;         ///< The cursor to pass as api parameter to get the next set of results.
  UT_array *outputs;    ///< output IDs
} get_outputs_id_t;

/**
 * @brief The response of get outputs from address
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;              ///< Error message if is_error is True
    get_outputs_id_t *output_ids;  ///< an output object if is_error is False
  } u;
} res_outputs_id_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocats an output address response object
 *
 * @return res_outputs_id_t*
 */
res_outputs_id_t *res_outputs_new();

/**
 * @brief Frees an output address response object
 *
 * @param[in] res A response object
 */
void res_outputs_free(res_outputs_id_t *res);

/**
 * @brief Gets an output id by given index
 *
 * @param[in] res A response object
 * @param[in] index The index of output id
 * @return char* A pointer to a string
 */
char *res_outputs_output_id(res_outputs_id_t *res, size_t index);

/**
 * @brief Gets the output id count
 *
 * @param[in] res A response object
 * @return size_t The length of output ids
 */
size_t res_outputs_output_id_count(res_outputs_id_t *res);

/**
 * @brief Deserialize outputs
 *
 * @param[in] j_str A string of a JSON object
 * @param[out] res The response object
 * @return int 0 on successful
 */
int deser_outputs(char const *const j_str, res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] addr An address in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given NFT address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] addr An NFT address in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_nft_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Alias address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] addr An Alias address in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_alias_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Foundry address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] addr A Foundry address in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_foundry_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given NFT ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] nft_id An NFT id in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_nft_id(iota_client_conf_t const *conf, char const nft_id[], res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Alias ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] alias_id An Alias id in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_alias_id(iota_client_conf_t const *conf, char const alias_id[], res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Foundry ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] foundry_id A Foundry id in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_foundry_id(iota_client_conf_t const *conf, char const foundry_id[], res_outputs_id_t *res);

#ifdef __cplusplus
}
#endif

#endif
