#ifndef __CLIENT_API_RES_ERR_H__
#define __CLIENT_API_RES_ERR_H__

#include <stdint.h>

#include "cJSON.h"

// the key of data object in json
static char const *const key_data = "data";
// the key of error object in json
static char const *const key_error = "error";

typedef struct {
  uint32_t code;
  char *msg;
} res_err_t;

#ifdef __cplusplus
extern "C" {
#endif

void res_err_free(res_err_t *err);

res_err_t *deser_error(cJSON *j_obj);

#ifdef __cplusplus
}
#endif

#endif
