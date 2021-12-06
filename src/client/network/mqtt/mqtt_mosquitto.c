// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client/network/mqtt/mqtt.h"

struct mqtt_client {
  struct mosquitto *mosq;
  mqtt_client_config_t *config;
  void (*mqtt_callback)(mqtt_client_event_t *event, void *userdata);
  void *cb_userdata;
};

/* Callback called when the client receives a CONNACK message from the broker. */
void on_mqtt_connect(struct mosquitto *mosq, void *client, int reason_code) {
  /* Print out the connection result.*/
  printf("[%s:%d]: Connect Mqtt: %s\n", __func__, __LINE__, mosquitto_connack_string(reason_code));
  // Create an event with eventid corresponding to MQTT Connected
  mqtt_client_event_t *mqtt_event = (mqtt_client_event_t *)malloc(sizeof(mqtt_client_event_t));
  if (reason_code == 0) {
    mqtt_event->event_id = MQTT_CONNECTED;
  } else {
    mqtt_event->event_id = MQTT_ERROR;
    const char *con_ack = mosquitto_connack_string(reason_code);
    mqtt_event->data_len = strlen(con_ack);
    mqtt_event->data = (void *)con_ack;
  }
  (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
  free(mqtt_event);
}

/* Callback called when the broker sends a SUBACK in response to a SUBSCRIBE. */
void on_mqtt_subscribe(struct mosquitto *mosq, void *client, int mid, int qos_count, const int *granted_qos) {
  int i;
  bool have_subscription = false;

  /* Check if subscription granted by broker. */
  for (i = 0; i < qos_count; i++) {
    if (granted_qos[i] <= 2) {
      have_subscription = true;
      // Create an event with eventid corresponding to MQTT Subscribed
      mqtt_client_event_t *mqtt_event = (mqtt_client_event_t *)malloc(sizeof(mqtt_client_event_t));
      mqtt_event->event_id = MQTT_SUBSCRIBED;
      mqtt_event->msg_id = mid;
      mqtt_event->qos = granted_qos[i];
      (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
      free(mqtt_event);
    }
  }
  if (have_subscription == false) {
    /* The broker rejected subscription. */
    printf("[%s:%d]: Error: Subscription rejected.\n", __func__, __LINE__);
  }
}

/* Callback called when a topic is unsubscribed. */
void on_mqtt_unsubscribe(struct mosquitto *mosq, void *client, int mid) {
  mqtt_client_event_t *mqtt_event = (mqtt_client_event_t *)malloc(sizeof(mqtt_client_event_t));
  mqtt_event->event_id = MQTT_UNSUBSCRIBED;
  mqtt_event->msg_id = mid;
  (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
  free(mqtt_event);
}

/* Callback called when the client receives a message. */
void on_mqtt_message(struct mosquitto *mosq, void *client, const struct mosquitto_message *msg) {
  /* Pass data to callback function */
  mqtt_client_event_t *mqtt_event = (mqtt_client_event_t *)malloc(sizeof(mqtt_client_event_t));
  mqtt_event->event_id = MQTT_DATA;
  mqtt_event->topic_len = strlen(msg->topic);
  mqtt_event->topic = msg->topic;
  mqtt_event->data_len = msg->payloadlen;
  mqtt_event->data = msg->payload;
  mqtt_event->msg_id = msg->mid;
  mqtt_event->qos = msg->qos;
  mqtt_event->retain = msg->retain;
  (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
  free(mqtt_event);
}

void on_mqtt_disconnect(struct mosquitto *mosq, void *client, int mid) {
  mqtt_client_event_t *mqtt_event = (mqtt_client_event_t *)malloc(sizeof(mqtt_client_event_t));
  mqtt_event->event_id = MQTT_DISCONNECTED;
  mqtt_event->msg_id = mid;
  (((mqtt_client_handle_t)client)->mqtt_callback)(mqtt_event, ((mqtt_client_handle_t)client)->cb_userdata);
  free(mqtt_event);
}

mqtt_client_handle_t mqtt_init(mqtt_client_config_t *config) {
  int rc;
  /* Required before calling other mosquitto functions */
  mosquitto_lib_init();

  /* Create a new client instance.
   * client id for communicating to the broker
   * clean session = true -> the broker should remove old sessions when we connect
   * obj = NULL -> we aren't passing any of our private data for callbacks
   */
  mqtt_client_handle_t client = (struct mqtt_client *)malloc(sizeof(struct mqtt_client));
  if (client == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  // Reference config paramters in client instance
  client->config = config;
  /* Create a new mosquitto instance.
   * client id for communicating to the broker
   * clean session = true -> the broker should remove old sessions when we connect
   * obj = client -> client instance to be used in callback functions
   */
  client->mosq = mosquitto_new(client->config->client_id, true, client);
  if (client->mosq == NULL) {
    printf("[%s:%d]: Error: Mosquitto new, cannot be initialized.\n", __func__, __LINE__);
    goto end;
  }
  if (client->config->username != NULL) {
    rc = mosquitto_username_pw_set(client->mosq, client->config->username, client->config->password);
    if (rc != MOSQ_ERR_SUCCESS) {
      mosquitto_destroy(client->mosq);
      printf("[%s:%d]: Mqtt set username password, Error: %s\n", __func__, __LINE__, mosquitto_strerror(rc));
      goto end;
    }
  }
  /* Configure callbacks. This should be done before connecting ideally. */
  mosquitto_connect_callback_set(client->mosq, on_mqtt_connect);
  mosquitto_subscribe_callback_set(client->mosq, on_mqtt_subscribe);
  mosquitto_unsubscribe_callback_set(client->mosq, on_mqtt_unsubscribe);
  mosquitto_message_callback_set(client->mosq, on_mqtt_message);
  mosquitto_disconnect_callback_set(client->mosq, on_mqtt_disconnect);
  return client;

end:
  free(client);
  return NULL;
}

int mqtt_register_cb(mqtt_client_handle_t client, void (*callback)(mqtt_client_event_t *event, void *userdata),
                     void *userdata) {
  client->mqtt_callback = callback;
  client->cb_userdata = userdata;
  return 0;
}

int mqtt_subscribe(mqtt_client_handle_t client, int *mid, char *topic, int qos) {
  int rc = mosquitto_subscribe(client->mosq, mid, topic, qos);
  if (rc != MOSQ_ERR_SUCCESS) {
    printf("[%s:%d]: Error subscribing: %s\n", __func__, __LINE__, mosquitto_strerror(rc));
    return -1;
  }
  return 0;
}

int mqtt_unsubscribe(mqtt_client_handle_t client, int *mid, char *topic) {
  int rc = mosquitto_unsubscribe(client->mosq, mid, topic);
  if (rc != MOSQ_ERR_SUCCESS) {
    printf("[%s:%d]: Error unsubscribing: %s\n", __func__, __LINE__, mosquitto_strerror(rc));
    return -1;
  }
  return 0;
}

int mqtt_start(mqtt_client_handle_t client) {
  int rc;
  /* Connect MQTT with the specified url, port and keep alive time. */
  rc = mosquitto_connect(client->mosq, client->config->host, client->config->port, client->config->keepalive);
  if (rc != MOSQ_ERR_SUCCESS) {
    mosquitto_destroy(client->mosq);
    mosquitto_lib_cleanup();
    printf("[%s:%d]: Mqtt connect, Error: %s\n", __func__, __LINE__, mosquitto_strerror(rc));
    return -1;
  }

  /* Run the network loop in a non-blocking call. */
  mosquitto_loop_start(client->mosq);

  return 0;
}

int mqtt_stop(mqtt_client_handle_t client) {
  // Disconnect from the broker.
  mosquitto_disconnect(client->mosq);
  // Stop the network loop
  mosquitto_loop_stop(client->mosq, false);
  return 0;
}

int mqtt_destroy(mqtt_client_handle_t client) {
  // Disconnect from the broker.
  mosquitto_disconnect(client->mosq);
  // Stop the network loop
  mosquitto_loop_stop(client->mosq, false);
  // Call to free memory associated with a mosquitto client instance.
  mosquitto_destroy(client->mosq);
  // Call to free resources associated with the library.
  mosquitto_lib_cleanup();
  // Free client instance
  free(client);
  return 0;
}