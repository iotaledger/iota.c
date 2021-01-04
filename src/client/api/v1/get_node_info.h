#ifndef __CLIENT_API_V1_INFO_H__
#define __CLIENT_API_V1_INFO_H__

#include <stdbool.h>
#include <stdint.h>

#include "utarray.h"

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/types.h"

typedef struct {
  char name[32];
  char version[32];
  bool is_healthy;
  char network_id[32];
  uint64_t min_pow_score;
  uint64_t latest_milestone_index;
  uint64_t solid_milestone_index;
  uint64_t pruning_milestone_index;
  UT_array *features;
} get_node_info_t;

typedef struct {
  bool is_error;
  union {
    res_err_t *error;
    get_node_info_t *output_node_info;
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

#ifdef __cplusplus
}
#endif

#endif
