#ifndef __CLIENT_API_V1_INFO_H__
#define __CLIENT_API_V1_INFO_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/types.h"

typedef struct {
  char name[32];
  char version[32];
  bool is_healthy;
  uint8_t network_id;
  byte_t latest_milestone_id[32];
  uint64_t latest_milestone_index;
  byte_t solid_milestone_id[32];
  uint64_t solid_milestone_index;
  uint64_t pruning_milestone_index;
  char features[128];
} res_node_info_t;

#ifdef __cplusplus
extern "C" {
#endif

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
