/*
 * Copyright (c) 2019 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

#include "cclient/api/core/core_init.h"
#include "cclient/api/core/logger.h"

static char const *client_path = "/";
static char const *client_content_type = "application/json";

iota_client_service_t *iota_client_core_init(char const *host, uint16_t port, char const *ca_pem) {
  iota_client_service_t *service = (iota_client_service_t *)malloc(sizeof(iota_client_service_t));
  if (service == NULL) {
    return NULL;
  }
  strncpy(service->http.host, host, HOST_MAX_LEN);
  strcpy(service->http.content_type, client_content_type);
  strcpy(service->http.accept, client_content_type);
  strcpy(service->http.path, client_path);
  service->http.port = port;
  service->http.ca_pem = ca_pem;
  service->serializer_type = SR_JSON;
  service->http.api_version = 1;
  iota_client_service_init(service);
  return service;
}

void iota_client_core_destroy(iota_client_service_t **service) {
  if (service && *service) {
    free(*service);
    *service = NULL;
  }
}
