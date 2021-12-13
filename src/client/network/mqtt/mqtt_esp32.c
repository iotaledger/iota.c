// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "mqtt_client.h"

#include "client/network/mqtt/mqtt.h"

static const char *TAG = "MQTT_CLIENT";

struct mqtt_client {
  esp_mqtt_client_handle_t esp32_mqtt_client;
  mqtt_client_config_t *config;
  void (*mqtt_callback)(mqtt_client_event_t *event, void *userdata);
  void *cb_userdata;
};

static void log_error_if_nonzero(const char *message, int error_code) {
  if (error_code != 0) {
    ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
  }
}

static esp_err_t mqtt_event_handler_cb(esp_mqtt_event_handle_t event, void *client) {
  mqtt_client_event_t *mqtt_event = (mqtt_client_event_t *)malloc(sizeof(mqtt_client_event_t));
  switch (event->event_id) {
    case MQTT_EVENT_CONNECTED:
      ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
      // Create an event with eventid corresponding to MQTT Connected
      mqtt_event->event_id = MQTT_CONNECTED;
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      break;
    case MQTT_EVENT_DISCONNECTED:
      ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
      mqtt_event->event_id = MQTT_DISCONNECTED;
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      break;
    case MQTT_EVENT_SUBSCRIBED:
      ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
      mqtt_event->event_id = MQTT_SUBSCRIBED;
      mqtt_event->msg_id = event->msg_id;
      // Qos not present in current submodule version of esp_mqtt
      // mqtt_event->qos = event->qos;
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      break;
    case MQTT_EVENT_UNSUBSCRIBED:
      ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
      mqtt_event->event_id = MQTT_UNSUBSCRIBED;
      mqtt_event->msg_id = event->msg_id;
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      break;
    case MQTT_EVENT_PUBLISHED:
      ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
      mqtt_event->event_id = MQTT_PUBLISHED;
      mqtt_event->msg_id = event->msg_id;
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      break;
    case MQTT_EVENT_DATA:
      ESP_LOGI(TAG, "MQTT_EVENT_DATA");
      mqtt_event->event_id = MQTT_DATA;
      mqtt_event->topic_len = event->topic_len;
      mqtt_event->topic = event->topic;
      mqtt_event->data_len = event->data_len;
      mqtt_event->data = (void *)event->data;
      mqtt_event->msg_id = event->msg_id;
      // Qos not present in current submodule version of esp_mqtt
      // mqtt_event->qos = event->qos;
      mqtt_event->retain = event->retain;
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      break;
    case MQTT_EVENT_ERROR:
      ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
      if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
        log_error_if_nonzero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
        log_error_if_nonzero("reported from tls stack", event->error_handle->esp_tls_stack_err);
        log_error_if_nonzero("captured as transport's socket errno", event->error_handle->esp_transport_sock_errno);
        ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
      }
      mqtt_event->event_id = MQTT_ERROR;
      mqtt_event->data_len = strlen(strerror(event->error_handle->esp_transport_sock_errno));
      mqtt_event->data = (void *)strerror(event->error_handle->esp_transport_sock_errno);
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      break;
    default:
      ESP_LOGI(TAG, "Other event id:%d", event->event_id);
      break;
  }
  free(mqtt_event);
  return ESP_OK;
}

// handler_args is the user define context specified in esp_mqtt_client_register_event
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
  ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%d", base, event_id);
  mqtt_event_handler_cb(event_data, handler_args);
}

mqtt_client_handle_t mqtt_init(mqtt_client_config_t *config) {
  /* Create a new client instance.
   * client id for communicating to the broker
   * clean session = true -> the broker should remove old sessions when we connect
   * obj = NULL -> we aren't passing any of our private data for callbacks
   */
  mqtt_client_handle_t client = (struct mqtt_client *)malloc(sizeof(struct mqtt_client));
  if (client == NULL) {
    ESP_LOGD(TAG, "OOM");
    return NULL;
  }

  // Reference config paramters in client instance
  client->config = config;

  esp_mqtt_client_config_t mqtt_cfg = {.host = client->config->host,
                                       .port = client->config->port,
                                       .client_id = client->config->client_id,
                                       .keepalive = client->config->keepalive,
                                       .username = client->config->username,
                                       .password = client->config->password};

  client->esp32_mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
  // Register call back for all events
  esp_mqtt_client_register_event(client->esp32_mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, client);

  return client;
}

int mqtt_register_cb(mqtt_client_handle_t client, void (*callback)(mqtt_client_event_t *event, void *userdata),
                     void *userdata) {
  client->mqtt_callback = callback;
  client->cb_userdata = userdata;
  return 0;
}

int mqtt_subscribe(mqtt_client_handle_t client, int *mid, char *topic, int qos) {
  // esp_mqtt_client_subscribe returns mid if subscription successful else returns -1
  int msg_id;
  msg_id = esp_mqtt_client_subscribe(client->esp32_mqtt_client, topic, qos);
  if (msg_id != -1) {
    if(mid != NULL) {
      *mid = msg_id;
    }
    return 0;
  } else {
    ESP_LOGD(TAG, "Error subscribing topic : %s", topic);
    return -1;
  }
}

int mqtt_unsubscribe(mqtt_client_handle_t client, int *mid, char *topic) {
  int msg_id;
  msg_id = esp_mqtt_client_unsubscribe(client->esp32_mqtt_client, topic);
  if (msg_id != -1) {
    if(mid != NULL) {
      *mid = msg_id;
    }
    return 0;
  } else {
    ESP_LOGD(TAG, "Error unsubscribing topic : %s", topic);
    return -1;
  }
}

int mqtt_start(mqtt_client_handle_t client) {
  // This is a non blocking call
  esp_err_t rc = esp_mqtt_client_start(client->esp32_mqtt_client);
  if (rc == ESP_OK) {
    return 0;
  } else {
    ESP_ERROR_CHECK_WITHOUT_ABORT(rc);
    return -1;
  }
}

int mqtt_stop(mqtt_client_handle_t client) {
  esp_err_t rc = esp_mqtt_client_disconnect(client->esp32_mqtt_client);
  if (rc != ESP_OK) {
    ESP_ERROR_CHECK_WITHOUT_ABORT(rc);
    return -1;
  }
  rc = esp_mqtt_client_stop(client->esp32_mqtt_client);
  if (rc != ESP_OK) {
    ESP_ERROR_CHECK_WITHOUT_ABORT(rc);
    return -1;
  }
  return 0;
}

int mqtt_destroy(mqtt_client_handle_t client) {
  esp_err_t rc = esp_mqtt_client_disconnect(client->esp32_mqtt_client);
  if (rc != ESP_OK) {
    ESP_ERROR_CHECK_WITHOUT_ABORT(rc);
    return -1;
  }
  rc = esp_mqtt_client_stop(client->esp32_mqtt_client);
  if (rc != ESP_OK) {
    ESP_ERROR_CHECK_WITHOUT_ABORT(rc);
    return -1;
  }
  rc = esp_mqtt_client_destroy(client->esp32_mqtt_client);
  if (rc != ESP_OK) {
    ESP_ERROR_CHECK_WITHOUT_ABORT(rc);
    return -1;
  }
  return 0;
}
