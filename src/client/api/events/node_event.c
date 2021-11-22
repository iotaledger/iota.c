// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "client/api/events/node_event.h"
#include "client/network/mqtt/mqtt.h"

/**
 * @brief Event client session
 *
 */
struct event_client {
  mqtt_client_handle_t mqtt_client;
  void (*event_callback_t)(event_client_event_t *event);
};

void mqtt_callback(mqtt_client_event_t *event, void *client) {
  event_client_event_t *node_event = (event_client_event_t *)malloc(sizeof(event_client_event_t));
  switch (event->event_id) {
    case MQTT_ERROR:
      node_event->event_id = NODE_EVENT_ERROR;
      node_event->client = ((event_client_handle_t)client);
      (((event_client_handle_t)client)->event_callback_t)(node_event);
      break;
    case MQTT_CONNECTED:
      node_event->event_id = NODE_EVENT_CONNECTED;
      node_event->client = ((event_client_handle_t)client);
      (((event_client_handle_t)client)->event_callback_t)(node_event);
      break;
    case MQTT_DISCONNECTED:
      node_event->event_id = NODE_EVENT_DISCONNECTED;
      node_event->client = ((event_client_handle_t)client);
      (((event_client_handle_t)client)->event_callback_t)(node_event);
      break;
    case MQTT_SUBSCRIBED:
      node_event->event_id = NODE_EVENT_SUBSCRIBED;
      node_event->msg_id = event->msg_id;
      node_event->qos = event->qos;
      node_event->client = ((event_client_handle_t)client);
      (((event_client_handle_t)client)->event_callback_t)(node_event);
      break;
    case MQTT_UNSUBSCRIBED:
      node_event->event_id = NODE_EVENT_UNSUBSCRIBED;
      node_event->msg_id = event->msg_id;
      node_event->client = ((event_client_handle_t)client);
      (((event_client_handle_t)client)->event_callback_t)(node_event);
      break;
    case MQTT_PUBLISHED:
      break;
    case MQTT_DATA:
      node_event->event_id = NODE_EVENT_DATA;
      node_event->client = ((event_client_handle_t)client);
      node_event->topic_len = event->topic_len;
      node_event->topic = event->topic;
      node_event->data_len = event->data_len;
      node_event->data = event->data;
      node_event->msg_id = event->msg_id;
      node_event->qos = event->qos;
      node_event->retain = event->retain;
      (((event_client_handle_t)client)->event_callback_t)(node_event);
      break;
    default:
      break;
  }
  free(node_event);
}

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

int event_register_cb(event_client_handle_t client, void (*callback)(event_client_event_t *event)) {
  client->event_callback_t = callback;
  mqtt_register_cb(client->mqtt_client, mqtt_callback, client);
  return 0;
}

int event_subscribe(event_client_handle_t client, int *mid, char *topic, int qos) {
  // Call to MQTT network layer
  return mqtt_subscribe(client->mqtt_client, mid, topic, qos);
}

int event_unsubscribe(event_client_handle_t client, int *mid, char *topic) {
  // Call to MQTT network layer
  return mqtt_unsubscribe(client->mqtt_client, mid, topic);
}

int event_start(event_client_handle_t client) {
  // Call to MQTT network layer
  return mqtt_start(client->mqtt_client);
}

int event_stop(event_client_handle_t client) {
  // Call to MQTT network layer
  return mqtt_stop(client->mqtt_client);
}

int event_destroy(event_client_handle_t client) {
  mqtt_destroy(client->mqtt_client);
  free(client);
  return 0;
}