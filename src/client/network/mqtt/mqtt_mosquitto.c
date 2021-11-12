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
  sub_topic_list_t topic_list;
};

/* Callback called when the client receives a CONNACK message from the broker. */
void on_mqtt_connect(struct mosquitto *mosq, void *client, int reason_code) {
  int rc;
  /* Print out the connection result.*/
  printf("[%s:%d]: Connect Mqtt: %s\n", __func__, __LINE__, mosquitto_connack_string(reason_code));
  if (reason_code == 0) {
    /* Making subscriptions in the on_connect() callback means that if the
     * connection drops and is automatically resumed by the client, then the
     * subscriptions will be recreated when the client reconnects. */
    for (int i = 0; i < ((mqtt_client_handle_t)client)->topic_list.topic_count; i++) {
      printf("[%s:%d]: Trying to subscribe topic : %s\n", __func__, __LINE__,
             ((mqtt_client_handle_t)client)->topic_list.sub_topic_array[i].topic);
      rc = mosquitto_subscribe(mosq, NULL, ((mqtt_client_handle_t)client)->topic_list.sub_topic_array[i].topic,
                               ((mqtt_client_handle_t)client)->topic_list.sub_topic_array[i].qos);
      if (rc != MOSQ_ERR_SUCCESS) {
        printf("[%s:%d]: Error subscribing: %s\n", __func__, __LINE__, mosquitto_strerror(rc));
      }
    }
  }
}

/* Callback called when the broker sends a SUBACK in response to a SUBSCRIBE. */
void on_mqtt_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos) {
  int i;
  bool have_subscription = false;

  /* Check if subscription granted by broker. */
  for (i = 0; i < qos_count; i++) {
    if (granted_qos[i] <= 2) {
      have_subscription = true;
      printf("[%s:%d]: Subscribed topic, granted qos = %d\n", __func__, __LINE__, granted_qos[i]);
    }
  }
  if (have_subscription == false) {
    /* The broker rejected subscription. */
    printf("[%s:%d]: Error: Subscription rejected.\n", __func__, __LINE__);
  }
}

/* Callback called when the client receives a message. */
void on_mqtt_message(struct mosquitto *mosq, void *client, const struct mosquitto_message *msg) {
  /* Handling call back functions*/
  printf("Received message : %s \n", (char *)msg->payload);
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
  mosquitto_message_callback_set(client->mosq, on_mqtt_message);
  // Clear topic count
  client->topic_list.topic_count = 0;
  return client;

end:
  free(client);
  return NULL;
}

int mqtt_start(mqtt_client_handle_t client) {
  int rc;
  /* Connect mqtt with the specified url, port and keep alive time. */
  rc = mosquitto_connect(client->mosq, client->config->host, client->config->port, client->config->keepalive);
  if (rc != MOSQ_ERR_SUCCESS) {
    mosquitto_destroy(client->mosq);
    mosquitto_lib_cleanup();
    printf("[%s:%d]: Mqtt connect, Error: %s\n", __func__, __LINE__, mosquitto_strerror(rc));
    return -1;
  }

  /* Run the network loop in a blocking call. */
  mosquitto_loop_forever(client->mosq, -1, 1);

  mosquitto_lib_cleanup();
  return 0;
}

int mqtt_subscribe(mqtt_client_handle_t client, char *topic, int qos) {
  client->topic_list.topic_count++;
  if (client->topic_list.topic_count > MAX_TOPIC_COUNT) {
    printf("[%s:%d]: Error : Max topic count reached.\n", __func__, __LINE__);
    return -1;
  }
  client->topic_list.sub_topic_array[client->topic_list.topic_count - 1].topic = topic;
  client->topic_list.sub_topic_array[client->topic_list.topic_count - 1].qos = qos;
  return 0;
}

int mqtt_destroy(mqtt_client_handle_t client) {
  // Clear topic count
  client->topic_list.topic_count = 0;
  // Disconnect from the broker.
  mosquitto_disconnect(client->mosq);
  // Call to free memory associated with a mosquitto client instance.
  mosquitto_destroy(client->mosq);
  // Call to free resources associated with the library.
  mosquitto_lib_cleanup();
  // Free client insatnce
  free(client);
  return 0;
}