// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_NETWORK_MQTT_H__
#define __CLIENT_NETWORK_MQTT_H__

/**
 * @brief Abstract layer of mqtt client for IOTA client
 *
 */

#include <mosquitto.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_TOPIC_COUNT 50

typedef struct {
  char const *host;       ///< Mqtt host url
  uint16_t port;          ///< Mqtt port to connect, usually it is 1883
  const char *client_id;  ///< The client id to use, or NULL if a random client id should be generated
  uint8_t keepalive;      ///< The number of seconds after which the broker should send a PING message to the client
  const char *username;   ///< The username string, or NULL for no username authentication
  const char *password;   ///< The password string, or NULL for an empty password.
} mqtt_client_config_t;

typedef struct {
  char *topic; ///< topic sctring, support wild cards
  void (*callback)(void *payload); ///< Callback function assosiated with the topic
} sub_topic_t;

typedef struct{
  int topic_count; ///< Total subscribed topic count update variable
  sub_topic_t sub_topic_array[MAX_TOPIC_COUNT]; ///< Buffer enough for holding total topics to subscribe
}sub_topic_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize mqtt clients and call backs.
 *
 * @return int 0 on success
 */
int mqtt_init(mqtt_client_config_t const *const config);

/**
 * @brief Connects to mqtt broker
 *
 * @param[in] config mqtt server config
 * @return int 0 on success
 */
int mqtt_start(mqtt_client_config_t const *const config);

/**
 * @brief Subscribe to a topic and register callback
 *
 * @param[in] topic topic for subscribing, support wildcards
 * @param[in] callback callback when a message arrived in the specified topic
 * @param[in] qos Quality of Service for the subscription
 * @return int 0 on success
 */
int mqtt_subscribe(char *topic, void (*callback)(void *), int qos);

/** @brief Disconnect mqtt broker
 *
 * @return int 0 on success
 */
int mqtt_stop(void);

#ifdef __cplusplus
}
#endif

#endif
