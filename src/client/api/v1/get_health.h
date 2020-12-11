#ifndef __CLIENT_API_V1_HEALTH_H__
#define __CLIENT_API_V1_HEALTH_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/client_service.h"
#include "core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

int get_health(iota_client_conf_t const *conf, bool *health);

#ifdef __cplusplus
}
#endif

#endif
