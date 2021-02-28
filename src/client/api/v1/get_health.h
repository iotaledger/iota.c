// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_HEALTH_H__
#define __CLIENT_API_V1_HEALTH_H__

#include <stdbool.h>
#include <stdint.h>

#include "client/client_service.h"
#include "core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Returns the health of the node.
 *
 * A node considers itself healthy if its current confirmed milestone is at most two delta away from the latest known
 * milestone, has at least one ongoing gossip stream and the latest known milestone is newer than 5 minutes.
 *
 * @param[in] conf The endpoint configuration
 * @param[out] health Is node health?
 * @return int 0 on success
 */
int get_health(iota_client_conf_t const *conf, bool *health);

#ifdef __cplusplus
}
#endif

#endif
