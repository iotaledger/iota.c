#ifndef __CLIENT_API_V1_TIPS_H__
#define __CLIENT_API_V1_TIPS_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "client/network/http.h"

#define STR_TIP_MSG_LEN 64

typedef struct {
  char tip1[STR_TIP_MSG_LEN];
  char tip2[STR_TIP_MSG_LEN];
} get_tips_t;

typedef struct {
  bool is_error;
  union {
    res_err_t *error;
    get_tips_t tips;
  } tips_u;
} res_tips_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets tips
 *
 * Returns two non-lazy tips. In case the node can only provide one tip, tip1 and tip2 are identical.
 *
 * @param[in] conf The client endpoint configuration
 * @param[out] res A response object of tips object
 * @return int 0 on success
 */
int get_tips(iota_client_conf_t const *conf, res_tips_t *res);

/**
 * @brief tips response deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res A response object of tips object
 * @return int 0 on success
 */
int deser_get_tips(char const *const j_str, res_tips_t *res);

res_tips_t *res_tips_new();

void res_tips_free(res_tips_t *tips);

#ifdef __cplusplus
}
#endif

#endif
