#ifndef __CLIENT_SERVICE_H__
#define __CLIENT_SERVICE_H__

#include <stdint.h>
#include <stdlib.h>

#define IOTA_ENDPOINT_MAX_LEN 256

typedef struct {
  char url[IOTA_ENDPOINT_MAX_LEN];
  uint16_t port;
} iota_client_conf_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
