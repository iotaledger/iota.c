#ifndef __CLIENT_API_INFO_H__
#define __CLIENT_API_INFO_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/response_error.h"
#include "client/client_service.h"

typedef struct {
  char name[32];
  char version[32];
  char net[32];
  bool is_healthy;
  bool is_synced;
  uint32_t peers;
  char coo_address[81];
  char lm[81];
  uint64_t lm_index;
  char lsm[81];
  uint64_t lsm_index;
  uint64_t pruning_index;
  uint64_t time;
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
