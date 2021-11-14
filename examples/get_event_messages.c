// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/events/node_event.h"

void callback(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("[%s:%d]: Node event network error : %s\n", __func__, __LINE__, (char *)event->data);
      break;
    case NODE_EVENT_CONNECTED:
      printf("[%s:%d]: Node event network connected\n", __func__, __LINE__);
      /* Making subscriptions in the on_connect() callback means that if the
       * connection drops and is automatically resumed by the client, then the
       * subscriptions will be recreated when the client reconnects. */
      event_subscribe(event->client, NULL, "milestones/latest", 1);
      break;
    case NODE_EVENT_DISCONNECTED:
      printf("[%s:%d]: Node event vetwork disonnected\n", __func__, __LINE__);
      break;
    case NODE_EVENT_SUBSCRIBED:
      printf("[%s:%d]: Subscribed topic, granted qos = %d\n", __func__, __LINE__, event->qos);
      break;
    case NODE_EVENT_UNSUBSCRIBED:
      printf("[%s:%d]: Un Subscribed topic\n", __func__, __LINE__);
      break;
    case NODE_EVENT_PUBLISHED:
      // To Do : Handle publish callback
      break;
    case NODE_EVENT_DATA:
      printf("[%s:%d]: Message arrived\n Topic : %s\n Message : %s\n", __func__, __LINE__, event->topic,
             (char *)event->data);
      // To Do : Parse Data
      break;
    default:
      break;
  }
}

int main(void) {
  event_client_config_t config = {
      .host = "mqtt.lb-0.h.chrysalis-devnet.iota.cafe", .port = 1883, .client_id = "iota_test_1234", .keepalive = 60};
  event_client_handle_t client = event_init(&config);
  event_register_cb(client, &callback);
  event_start(client);
  return 0;
}