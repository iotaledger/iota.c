// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_OUTPUTS_ID_H__
#define __CLIENT_API_RESTFUL_OUTPUTS_ID_H__

#include "utarray.h"

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/address.h"
#include "core/types.h"

#define INDEXER_OUTPUTS_API_PATH "/api/plugins/indexer/v1/outputs"
#define INDEXER_ALIASES_API_PATH "/api/plugins/indexer/v1/aliases"

/**
 * @brief All Query Params Type
 *
 */
typedef enum {
  QUERY_PARAM_ADDRESS = 0,    ///< The Bech32-encoded address that should be used to query outputs
  QUERY_PARAM_DUST_RET,       ///< The presence of dust return unlock condition
  QUERY_PARAM_DUST_RET_ADDR,  ///< The specific return address in the dust deposit return unlock condition
  QUERY_PARAM_SENDER,         ///< To query outputs based on bech32-encoded sender address.
  QUERY_PARAM_TAG,            ///< A tag block to search for outputs matching it
  QUERY_PARAM_PAGE_SIZE,      ///< The maximum amount of items returned in one api call
  QUERY_PARAM_CURSOR,         ///<  A cursor to start the query (confirmationMS+outputId.pageSize)
  QUERY_PARAM_STATE_CTRL,     ///< To query outputs based on bech32-encoded state controller address
  QUERY_PARAM_GOV,            ///< To query outputs based on bech32-encoded governor (governance controller) address
  QUERY_PARAM_ISSUER          ///< To query outputs based on bech32-encoded issuer address
} outputs_query_params_e;

/**
 * @brief A Query Param Onject
 *
 */
typedef struct {
  outputs_query_params_e type;  ///< The type of query param
  char *param;                  ///< Query param data
} outputs_query_params_t;

/**
 * @brief A list of outputs query parameters
 *
 */
typedef struct outputs_query_list {
  outputs_query_params_t *query_item;  ///< Points to a query parameter object
  struct outputs_query_list *next;     ///< Points to next query parameter object
} outputs_query_list_t;

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
 * @brief New outputs query params list
 *
 * @return outputs_query_list_t*
 */
outputs_query_list_t *outputs_query_list_new();

/**
 * @brief Add a querry parameter to the list
 *
 * @param[in] list A query item list
 * @param[in] type A query parameter type
 * @param[in] param A query parameter
 * @return int 0 on success
 */
int outputs_query_list_add(outputs_query_list_t **list, outputs_query_params_e type, char const *const param);

/**
 * @brief Get the length of query string present in list
 *
 * @param[in] list A query item list
 * @return size_t Query string len
 */
size_t get_outputs_query_str_len(outputs_query_list_t *list);

/**
 * @brief Get the query string present in list
 *
 * @param[in] list A query item list
 * @param[in] buf A buffer to hold query string
 * @param[in] buf_len The length of the buffer
 * @return size_t Query string len
 */
size_t get_outputs_query_str(outputs_query_list_t *list, char *buf, size_t buf_len);

/**
 * @brief Free query list
 *
 */
void outputs_query_list_free(outputs_query_list_t *list);

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
 * @param[in] list A list of optional query params
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_id(iota_client_conf_t const *conf, outputs_query_list_t *list, res_outputs_id_t *res);

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
 * @param[in] list A list of optional query params
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_alias(iota_client_conf_t const *conf, outputs_query_list_t *list, res_outputs_id_t *res);

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
