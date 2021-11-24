// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "client/api/events/node_event.h"
#include "client/api/events/sub_messages_referenced.h"
#include "client/api/events/sub_milestone_latest.h"
#include "client/api/events/sub_milestones_confirmed.h"

void process_event_data(event_client_event_t *event);

void callback(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("Node event network error : %s\n", (char *)event->data);
      break;
    case NODE_EVENT_CONNECTED:
      printf("Node event network connected\n");
      /* Making subscriptions in the on_connect() callback means that if the
       * connection drops and is automatically resumed by the client, then the
       * subscriptions will be recreated when the client reconnects. */
      event_subscribe(event->client, NULL, "milestones/latest", 1);
      event_subscribe(event->client, NULL, "milestones/confirmed", 1);
      event_subscribe(event->client, NULL, "messages/referenced", 1);
      break;
    case NODE_EVENT_DISCONNECTED:
      printf("Node event network disconnected\n");
      break;
    case NODE_EVENT_SUBSCRIBED:
      printf("Subscribed topic, granted qos = %d\n", event->qos);
      break;
    case NODE_EVENT_UNSUBSCRIBED:
      printf("Unsubscribed topic\n");
      break;
    case NODE_EVENT_PUBLISHED:
      // To Do : Handle publish callback
      break;
    case NODE_EVENT_DATA:
      printf("Message Received\nTopic : %s\n", event->topic);
      process_event_data(event);
      break;
    default:
      break;
  }
}

void process_event_data(event_client_event_t *event) {
  if (!strcmp(event->topic, "milestones/latest")) {
    milestone_latest_t res = {};
    if (parse_milestone_latest((char *)event->data, &res) == 0) {
      printf("Index :%u\nTimestamp : %lu\n", res.index, res.timestamp);
    }
  } else if (!strcmp(event->topic, "milestones/confirmed")) {
    milestone_confirmed_t res = {};
    if (parse_milestones_confirmed((char *)event->data, &res) == 0) {
      printf("Index :%u\nTimestamp : %lu\n", res.index, res.timestamp);
    }
  } else if (!strcmp(event->topic, "messages/referenced")) {
    msg_referenced_t *res = res_msg_referenced_new();
    if (res) {
      if (parse_messages_referenced((char *)event->data, res) == 0) {
        printf("Msg Id :%s\n", res->msg_id);
        size_t parents_count = res_msg_referenced_parents_len(res);
        for (size_t i = 0; i < parents_count; i++) {
          printf("Parent Id %zu : %s\n", i + 1, res_msg_referenced_parent_get(res, i));
        }
        printf("Inclusion State : %s\n", res->inclusion_state);
        printf("Is Solid : %s\n", res->is_solid ? "true" : "false");
        printf("Should Promote : %s\n", res->should_promote ? "true" : "false");
        printf("Should Reattach : %s\n", res->should_reattach ? "true" : "false");
        printf("Referenced Milestone : %ld\n", res->referenced_milestone);
      }
      res_msg_referenced_free(res);
    }
  }
}

int main(void) {
  event_client_config_t config = {
      .host = "mqtt.lb-0.h.chrysalis-devnet.iota.cafe", .port = 1883, .client_id = "iota_test_1234", .keepalive = 60};
  event_client_handle_t client = event_init(&config);
  event_register_cb(client, &callback);
  event_start(client);
  event_destroy(client);
  return 0;
}