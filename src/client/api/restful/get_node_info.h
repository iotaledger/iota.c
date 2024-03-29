// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_INFO_H__
#define __CLIENT_API_RESTFUL_INFO_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/restful/response_error.h"
#include "client/client_service.h"
#include "client/constants.h"
#include "core/utils/byte_buffer.h"
#include "utarray.h"

/**
 * @brief The milestone information
 *
 */
typedef struct {
  uint32_t index;                                      ///< A milestone index
  uint32_t timestamp;                                  ///< A milestone timestamp
  byte_t milestone_id[CRYPTO_BLAKE2B_256_HASH_BYTES];  ///< A milestone ID
} milestone_info_t;

/**
 * @brief The status of the connected node
 *
 */
typedef struct {
  milestone_info_t latest_milestone;     ///< The latest known milestone
  milestone_info_t confirmed_milestone;  ///< The current confirmed milestone
  uint32_t pruning_index;                ///< The milestone index at which the last pruning commenced
  bool is_healthy;                       ///< Whether the node is healthy.
} node_status_t;

/**
 * @brief The rent structure used by given node/network
 *
 */
typedef struct {
  uint16_t v_byte_cost;        ///< The Byte Cost
  uint8_t v_byte_factor_data;  ///< The Byte Factor Data
  uint8_t v_byte_factor_key;   ///< The Byte Factor Key
} rent_structure_t;

/**
 * @brief The protocol parameters of the node
 *
 */
typedef struct {
  uint8_t version;
  char network_name[32];   ///< The network name of this node
  char bech32hrp[16];      ///< The Bech32 HRP, the possible HRP string:
                           ///< `atoi` for testnet, `iota` for mainnet,
                           ///< `rms` for Shimmer testnet, `smr` for Shimmer.
  rent_structure_t rent;   ///< The rent structure
  uint32_t min_pow_score;  ///< The minimum pow score of the network
  uint8_t below_max_deep;  ///< The below max depth parameter of the network.
  uint64_t token_supply;   ///< TokenSupply defines the current token supply on the network.
} protocol_paramters_t;

/**
 * @brief The base token information
 *
 */
typedef struct {
  char name[32];           ///< The base token name
  char ticker_symbol[16];  ///< The base token ticker symbol
  char unit[16];           ///< The base token unit
  char subunit[16];        ///< The base token subunit
  uint32_t decimals;       ///< The base token amount of decimals
  bool use_metric_prefix;  ///< The base token uses the metric prefix
} base_token_t;

/**
 * @brief The metrics of the connected node.
 *
 */
typedef struct {
  float block_per_sec;             ///< The current rate of new blocks per second
  float referenced_block_per_sec;  ///< The current rate of referenced blocks per second
  float referenced_rate;           ///< The ratio of referenced blocks in relation to new blocks of the last confirmed
                                   ///< milestone
} node_metrics_t;

/**
 * @brief The general information about the connected node
 *
 */
typedef struct {
  char name[32];                           ///< The name of this node
  char version[32];                        ///< The version of this node
  uint8_t supported_protocol_version[32];  ///< The protocol versions this node supports.
  node_status_t status;                    ///< The status of the node
  protocol_paramters_t protocol_params;    ///< The protocol parameters
  base_token_t base_token;                 ///< Base token information
  node_metrics_t metrics;                  ///< The metrics of the node
  UT_array *features;                      ///< The features this node exposes
} get_node_info_t;

/**
 * @brief The response of get node info
 *
 */
typedef struct {
  bool is_error;  ///< True if got an error from the node.
  union {
    res_err_t *error;       ///< Error message if is_error is True
    get_node_info_t *info;  ///< node info if is_error is False
  } u;
} res_node_info_t;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Allocates node info response object
 * @return res_node_info_t*
 */
res_node_info_t *res_node_info_new();

/**
 * @brief Frees a node info response object
 * @param[in] res A response object
 */
void res_node_info_free(res_node_info_t *res);

/**
 * @brief Gets number of node features
 * @param[in] info Object with node info
 * @return The number of features
 */
size_t get_node_features_num(res_node_info_t *info);

/**
 * @brief Gets strings with node features
 * @param[in] info Object with node info
 * @param[in] idx Feature index
 * @return char* with features
 */

char *get_node_features_at(res_node_info_t *info, size_t idx);

/**
 * @brief Gets info API
 *
 * @param[in] conf The client endpoint configuration
 * @param[out] res A response object of node info
 * @return int 0 on success
 */
int get_node_info(iota_client_conf_t const *conf, res_node_info_t *res);

/**
 * @brief node info JSON deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object of node info
 * @return int 0 on success
 */
int deser_node_info(char const *const j_str, res_node_info_t *res);

/**
 * @brief Print Node Info
 *
 * @param[in] res res_node_info_t*
 * @param[in] indentation Tab indentation when printing node info
 */
void node_info_print(res_node_info_t *res, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
