// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __NODE_EVENT_H__
#define __NODE_EVENT_H__

/**
 * @brief Abstract layer of event api's for IOTA client
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/**
 * @brief Event ids for handling mqtt events
 *
 */
typedef enum {
  NODE_EVENT_ANY = -1,
  NODE_EVENT_ERROR = 0,    /*!< on error event, additional context: connection return code*/
  NODE_EVENT_CONNECTED,    /*!< connected event */
  NODE_EVENT_DISCONNECTED, /*!< disconnected event */
  NODE_EVENT_SUBSCRIBED,   /*!< subscribed event, additional context: msg_id */
  NODE_EVENT_UNSUBSCRIBED, /*!< unsubscribed event */
  NODE_EVENT_PUBLISHED,    /*!< published event, additional context:  msg_id */
  NODE_EVENT_DATA,         /*!< data event, additional context:
                                - msg_id               message id
                                - topic                pointer to the received topic
                                - topic_len            length of the topic
                                - data                 pointer to the received data
                                - data_len             length of the data for this event
                                - retain               retain flag of the message */
} event_client_event_id_t;

/**
 * @brief Event mqtt client config paramters
 *
 */
typedef struct {
  char const *host;       ///< Mqtt host url
  uint16_t port;          ///< Mqtt port to connect, usually it is 1883
  const char *client_id;  ///< The client id to use, or NULL if a random client id should be generated
  uint8_t keepalive;      ///< The number of seconds after which the broker should send a PING message to the client
  const char *username;   ///< The username string, or NULL for no username authentication
  const char *password;   ///< The password string, or NULL for an empty password.
} event_client_config_t;

/**
 * @brief Event client session handle
 *
 */
typedef struct event_client *event_client_handle_t;

/**
 * @brief Event configuration structure
 *
 */
typedef struct {
  event_client_event_id_t event_id; /*!< MQTT event type */
  event_client_handle_t client;     /*!< MQTT client handle for this event */
  char *data;                       /*!< Data associated with this event */
  int data_len;                     /*!< Length of the data for this event */
  char *topic;                      /*!< Topic associated with this event */
  int topic_len;                    /*!< Length of the topic associated with this event */
  int msg_id;                       /*!< MQTT messaged id of message */
  bool retain;                      /*!< Retained flag of the message associated with this event */
  int qos;                          /*!< qos of the messages associated with this event */
} event_client_event_t;

/**
 * @brief Event configuration structure handle
 *
 */
typedef event_client_event_t *event_client_event_handle_t;

/**
 * @brief Initialize events api mqtt library
 *
 * @param[in] config Mqtt client config paramters
 */
event_client_handle_t event_init(event_client_config_t *config);

/**
 * @brief Subscribe for a mqtt topic
 *
 * @param[in] client Event client instance
 * @param[in] topic Mqtt topic to subscribe
 * @param[in] qos QoS level to be used with the topic
 * @return 0 if Success
 */
int event_subscribe(event_client_handle_t client, char *topic, int qos);

/**
 * @brief Star mqtt connection
 *
 * @param[in] client Event client instance
 * @return 0 if Success
 */
int event_start(event_client_handle_t client);

/**
 * @brief Destroy event intance
 *
 * @param[in] client Event client instance
 * @return 0 if Success
 */
int event_destroy(event_client_handle_t client);

#endif