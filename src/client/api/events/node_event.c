// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "node_event.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "client/network/mqtt/mqtt.h"

/**
 * @brief Event client session
 *
 */
struct event_client {
  mqtt_client_handle_t mqtt_client;
  void (*event_callback_t)(event_client_event_handle_t event);
};

mqtt_client_config_t *set_client_config(event_client_config_t *config) {
  mqtt_client_config_t *event_conf = (mqtt_client_config_t *)malloc(sizeof(mqtt_client_config_t));
  if (event_conf == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  event_conf->host = config->host;
  event_conf->port = config->port;
  event_conf->client_id = config->client_id;
  event_conf->keepalive = config->keepalive;
  event_conf->username = config->username;
  event_conf->password = config->password;
  return event_conf;
}

event_client_handle_t event_init(event_client_config_t *config) {
  // Allocate client handle
  event_client_handle_t client = (struct event_client *)malloc(sizeof(struct event_client));
  if (client == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  // Prepare client config for mqt network layer
  mqtt_client_config_t *event_conf = set_client_config(config);
  if (event_conf == NULL) {
    free(client);
    return NULL;
  }
  // Initialize mqtt network layer
  client->mqtt_client = mqtt_init(event_conf);
  if (client->mqtt_client == NULL) {
    free(client);
    free(event_conf);
    return NULL;
  }

  return client;
}

int event_subscribe(event_client_handle_t client, char *topic, int qos) {
  // Call to mqtt network layer
  return mqtt_subscribe(client->mqtt_client, topic, qos);
}

int event_start(event_client_handle_t client) {
  // Call
  return mqtt_start(client->mqtt_client);
}

int event_destroy(event_client_handle_t client) {
  mqtt_destroy(client->mqtt_client);
  free(client);
  return 0;
}