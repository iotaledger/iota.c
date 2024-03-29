// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_OUTPUTS_ID_H__
#define __CLIENT_API_RESTFUL_OUTPUTS_ID_H__

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "core/address.h"
#include "utarray.h"

/**
 * @brief All Query Params Type
 *
 */
typedef enum {
  QUERY_PARAM_ADDRESS = 0,        ///< The Bech32-encoded address that should be used to query outputs
  QUERY_PARAM_ALIAS_ADDRESS,      ///< The alias address that should be used to query some outputs
  QUERY_PARAM_HAS_NATIVE_TOKENS,  ///< To filter outputs based on the presence of native tokens
  QUERY_PARAM_MIN_NATIVE_TOKENS,  ///< To filter outputs that have at least a certain number of distinct native tokens
  QUERY_PARAM_MAX_NATIVE_TOKENS,  ///< To filter outputs that have at most a certain number of distinct native tokens
  QUERY_PARAM_HAS_STORAGE_RET,    ///< The presence of storage return unlock condition
  QUERY_PARAM_STORAGE_RET_ADDR,   ///< The specific return address in the storage deposit return unlock condition
  QUERY_PARAM_HAS_TIMELOCK,       ///< To filter outputs based on the presence of timelock unlock condition
  QUERY_PARAM_TIMELOCKED_BEFORE,  ///< To return outputs that are timelocked before a certain Unix timestamp
  QUERY_PARAM_TIMELOCKED_AFTER,   ///< To return outputs that are timelocked after a certain Unix timestamp
  QUERY_PARAM_TIMELOCKED_BEFORE_MS,  ///< To return outputs that are timelocked before a certain milestone index
  QUERY_PARAM_TIMELOCKED_AFTER_MS,   ///< To return outputs that are timelocked after a certain milestone index
  QUERY_PARAM_HAS_EXP_COND,          ///< To filters outputs based on the presence of expiration unlock condition
  QUERY_PARAM_EXPIRES_BEFORE,        ///< To return outputs that expire before a certain Unix timestamp
  QUERY_PARAM_EXPIRES_AFTER,         ///< To return outputs that expire after a certain Unix timestamp
  QUERY_PARAM_EXPIRES_BEFORE_MS,     ///< To return outputs that expire before a certain milestone index
  QUERY_PARAM_EXPIRES_AFTER_MS,      ///< To return outputs that expire after a certain milestone index
  QUERY_PARAM_EXP_RETURN_ADDR,       ///< To filter outputs based on the presence of a specific return address in the
                                     ///< expiration unlock condition
  QUERY_PARAM_SENDER,                ///< To query outputs based on bech32-encoded sender address
  QUERY_PARAM_TAG,                   ///< A tag block to search for outputs matching it
  QUERY_PARAM_CREATED_BEFORE,        ///< To return outputs that were created before a certain Unix timestamp
  QUERY_PARAM_CREATED_AFTER,         ///< To return outputs that were created after a certain Unix timestamp
  QUERY_PARAM_PAGE_SIZE,             ///< The maximum amount of items returned in one api call
  QUERY_PARAM_CURSOR,                ///< A cursor to start the query (confirmationMS+outputId.pageSize)
  QUERY_PARAM_STATE_CTRL,            ///< To query outputs based on bech32-encoded state controller address
  QUERY_PARAM_GOV,    ///< To query outputs based on bech32-encoded governor (governance controller) address
  QUERY_PARAM_ISSUER  ///< To query outputs based on bech32-encoded issuer address
} outputs_query_params_e;

/**
 * @brief A Query Param Object
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
  uint32_t ledger_idx;  ///< The ledger index at which the output was queried at.
  uint32_t page_size;   ///< The number of output IDs returned in a single response.
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
 * @brief New a query parameter list
 *
 * The filter for output IDs
 *
 * @return NULL
 */
outputs_query_list_t *outputs_query_list_new();

/**
 * @brief Add a query parameter to the list
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
 * @return size_t The length of the query string
 */
size_t get_outputs_query_str_len(outputs_query_list_t *list);

/**
 * @brief Get the query string present in list
 *
 * @param[in] list A query item list
 * @param[in] buf A buffer to hold query string
 * @param[in] buf_len The length of the buffer
 * @return size_t the length in bytes that written to the buffer
 */
size_t get_outputs_query_str(outputs_query_list_t *list, char *buf, size_t buf_len);

/**
 * @brief Free query list
 *
 */
void outputs_query_list_free(outputs_query_list_t *list);

/**
 * @brief Allocates an output address response object
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
 * @brief Gets an output ID by a given index
 *
 * @param[in] res A response object
 * @param[in] index The index of the output ID
 * @return char* A pointer to a string
 */
char *res_outputs_output_id(res_outputs_id_t *res, size_t index);

/**
 * @brief Gets the output ID count
 *
 * @param[in] res A response object
 * @return size_t The length of output IDs
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
 * @param[in] indexer_path The api end-point indexer path
 * @param[in] list A list of optional query parameters
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_basic_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                      res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given NFT address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] indexer_path The api end-point indexer path
 * @param[in] addr An NFT address in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_nft_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                    res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Alias address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] indexer_path The api end-point indexer path
 * @param[in] list A list of optional query parameters
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_alias_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                      res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Foundry address
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] indexer_path The api end-point indexer path
 * @param[in] list A list of optional query parameters
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_foundry_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                        res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given NFT ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] indexer_path The api end-point indexer path
 * @param[in] nft_id An NFT ID in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_nft_id(iota_client_conf_t const *conf, char const *const indexer_path, char const nft_id[],
                            res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Alias ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] indexer_path The api end-point indexer path
 * @param[in] alias_id An Alias ID in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_alias_id(iota_client_conf_t const *conf, char const *const indexer_path, char const alias_id[],
                              res_outputs_id_t *res);

/**
 * @brief Gets output IDs from a given Foundry ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] indexer_path The api end-point indexer path
 * @param[in] foundry_id A Foundry ID in hex string format
 * @param[out] res A response object
 * @return int 0 on successful
 */
int get_outputs_from_foundry_id(iota_client_conf_t const *conf, char const *const indexer_path, char const foundry_id[],
                                res_outputs_id_t *res);

#ifdef __cplusplus
}
#endif

#endif
