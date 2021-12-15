// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __NODE_EVENT_H__
#define __NODE_EVENT_H__

/**
 * @brief The Abstract layer of the node event API.
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define TOPIC_MS_LATEST "milestones/latest"
#define TOPIC_MS_CONFIRMED "milestones/confirmed"
#define TOPIC_MS_REFERENCED "messages/referenced"
#define TOPIC_MESSAGES "messages"

/**
 * @brief Event IDs for handling IOTA Node events
 *
 */
typedef enum {
  NODE_EVENT_ANY = -1,
  NODE_EVENT_ERROR = 0,    /*!< on error event, additional context: connection return code*/
  NODE_EVENT_CONNECTED,    /*!< connected to a node broker */
  NODE_EVENT_DISCONNECTED, /*!< disconnected from the node broker */
  NODE_EVENT_SUBSCRIBED,   /*!< subscribed an event, additional context: msg_id */
  NODE_EVENT_UNSUBSCRIBED, /*!< unsubscribed an event */
  NODE_EVENT_PUBLISHED,    /*!< published an event, additional context:  msg_id */
  NODE_EVENT_DATA,         /*!< data event, additional context:
                                - msg_id               The message id
                                - topic                An pointer to the received topic
                                - topic_len            The length of the topic
                                - data                 An pointer to the received data
                                - data_len             The length of the data for this event
                                - retain               The retain flag of the message */
} event_client_event_id_t;

/**
 * @brief The event client configuration
 *
 */
typedef struct {
  char const *host;       ///< The broker host url
  uint16_t port;          ///< The broker port to connect with, usually it is 1883
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
 * @brief Event response object
 *
 */
typedef struct {
  event_client_event_id_t event_id; /*!< An event type */
  event_client_handle_t client;     /*!< The event handler of this event */
  void *data;                       /*!< The data associated with this event */
  int data_len;                     /*!< The length of the data for this event */
  char *topic;                      /*!< The topic associated with this event */
  int topic_len;                    /*!< The length of the topic associated with this event */
  int msg_id;                       /*!< The message ID */
  bool retain;                      /*!< The retained flag of the message associated with this event */
  int qos;                          /*!< The QoS of the message associated with this event */
} event_client_event_t;

/**
 * @brief Initialize event service
 *
 * @param[in] config MQTT client config paramters
 */
event_client_handle_t event_init(event_client_config_t *config);

/**
 * @brief Set the event callback handler
 *
 * @param[in] client The event client instance
 * @param[in] callback An event callback handler
 */
int event_register_cb(event_client_handle_t client, void (*callback)(event_client_event_t *event));

/**
 * @brief Subscribe an event
 *
 * @param[in] client The event client instance
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] topic A node topic to subscribe
 * @param[in] qos The QoS level for the topic
 * @return int 0 If Success
 */
int event_subscribe(event_client_handle_t client, int *mid, char *topic, int qos);

/**
 * @brief Unsubscribe an event
 *
 * @param[in] client The event client instance
 * @param[out] mid If not NULL, mid will return the message id of the topic subscription
 * @param[in] topic A node topic to subscribe
 * @return int 0 If Success
 */
int event_unsubscribe(event_client_handle_t client, int *mid, char *topic);

/**
 * @brief Connect to Node broker with the given config
 *
 * @param[in] client The event client instance
 * @return int 0 If Success
 */
int event_start(event_client_handle_t client);

/**
 * @brief Disconnect from the Node broker
 *
 * @param[in] client The event client instance
 * @return int 0 If Success
 */
int event_stop(event_client_handle_t client);

/**
 * @brief Stop and destroy event instance
 *
 * @param[in] client The event client instance
 * @return int 0 If Success
 */
int event_destroy(event_client_handle_t client);

#endif
