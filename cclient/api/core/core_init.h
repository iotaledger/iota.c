/*
 * Copyright (c) 2019 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

/**
 * @ingroup cclient_core
 *
 * @{
 *
 * @file
 * @brief
 *
 */
#ifndef CCLIENT_API_CORE_INIT_H
#define CCLIENT_API_CORE_INIT_H

#include "cclient/http/http.h"
#include "cclient/service.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This function should be called before using Core APIs.
 *
 *
 * @param[in] host The host of an iota node
 * @param[in] port The port of the host
 * @param[in] ca_pem  A Certificate Authority (CA) in PEM format.
 * @return #iota_client_service_t
 */
iota_client_service_t *iota_client_core_init(char const *host, uint16_t port, char const *ca_pem);

/**
 * @brief This function should be called for cleanup.
 *
 * @param[in] service A client service
 */
void iota_client_core_destroy(iota_client_service_t **service);

#ifdef __cplusplus
}
#endif

#endif  // CCLIENT_API_CORE_INIT_H

/** @} */