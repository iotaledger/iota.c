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

/**
 * @brief Event ids for handling mqtt events
 *
 */
typedef enum {
  MQTT_ANY = -1,
  MQTT_ERROR = 0,    /*!< on error event, additional context: connection return code*/
  MQTT_CONNECTED,    /*!< connected event */
  MQTT_DISCONNECTED, /*!< disconnected event */
  MQTT_SUBSCRIBED,   /*!< subscribed event, additional context: msg_id */
  MQTT_UNSUBSCRIBED, /*!< unsubscribed event */
  MQTT_PUBLISHED,    /*!< published event, additional context:  msg_id */
  MQTT_DATA,         /*!< data event, additional context:
                                - msg_id               message id
                                - topic                pointer to the received topic
                                - topic_len            length of the topic
                                - data                 pointer to the received data
                                - data_len             length of the data for this event
                                - retain               retain flag of the message */
} mqtt_event_id_t;

/**
 * @brief Event ids for handling mqtt events
 *
 */
typedef struct {
  mqtt_event_id_t event_id; /*!< MQTT event type */
  void *data;               /*!< Data associated with this event */
  int data_len;             /*!< Length of the data for this event */
  char *topic;              /*!< Topic associated with this event */
  int topic_len;            /*!< Length of the topic associated with this event */
  int msg_id;               /*!< MQTT messaged id of message */
  bool retain;              /*!< Retained flag of the message associated with this event */
  int qos;                  /*!< qos of the messages associated with this event */
} mqtt_client_event_t;

/**
 * @brief Mqtt config data
 *
 */
typedef struct {
  char const *host;       ///< Mqtt host url
  uint16_t port;          ///< Mqtt port to connect, usually it is 1883
  const char *client_id;  ///< The client id to use, or NULL if a random client id should be generated
  uint8_t keepalive;      ///< The number of seconds after which the broker should send a PING message to the client
  const char *username;   ///< The username string, or NULL for no username authentication
  const char *password;   ///< The password string, or NULL for an empty password.
} mqtt_client_config_t;

typedef struct mqtt_client *mqtt_client_handle_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize mqtt clients and call backs.
 *
 * @param[in] config client config
 * @return mqtt_client_handle_t
 */
mqtt_client_handle_t mqtt_init(mqtt_client_config_t *config);

/**
 * @brief Connects to mqtt broker
 *
 * @param[in] client client instance
 * @param[in] callback callback function
 * @param[in] userdata data to be passed as callback argument
 * @return int 0 on success
 */
int mqtt_register_cb(mqtt_client_handle_t client, void (*callback)(mqtt_client_event_t *event, void *userdata),
                     void *userdata);

/**
 * @brief Subscribe to a topic
 *
 * @param[in] client client instance
 * @param[in] mid if not NULL, mid will be set as the message id for the subscription topic
 * @param[in] topic topic for subscribing, support wildcards
 * @param[in] qos Quality of Service for the subscription
 * @return int 0 on success
 */
int mqtt_subscribe(mqtt_client_handle_t client, int *mid, char *topic, int qos);

/**
 * @brief Unsubscribe from a topic
 *
 * @param[in] client client instance
 * @param[in] mid if not NULL, mid will be set as the message id for the unsubscription topic
 * @param[in] topic topic for subscribing, support wildcards
 * @return int 0 on success
 */
int mqtt_unsubscribe(mqtt_client_handle_t client, int *mid, char *topic);

/**
 * @brief Connects to mqtt broker
 *
 * @param[in] client client instance
 * @return int 0 on success
 */
int mqtt_start(mqtt_client_handle_t client);

/**
 * @brief Disconnects from mqtt broker
 *
 * @param[in] client client instance
 * @return int 0 on success
 */
int mqtt_stop(mqtt_client_handle_t client);

/** @brief Disconnect mqtt broker
 *
 * @return int 0 on success
 */
int mqtt_destroy(mqtt_client_handle_t client);

#ifdef __cplusplus
}
#endif

#endif
