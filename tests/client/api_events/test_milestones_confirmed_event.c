// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>
#include <unity/unity.h>

#include "client/api/events/node_event.h"
#include "client/api/events/sub_milestones_confirmed.h"
#include "events_test_config.h"

void setUp(void) {}

void tearDown(void) {}

void test_milestones_confirmed_parser(void) {
  char *json_data = "{\"index\":1139767,\"timestamp\": 1637221249}";

  // Test for expected events response
  milestone_confirmed_t *res = res_milestones_confirmed_new();
  TEST_ASSERT_NOT_NULL(res);
  TEST_ASSERT_EQUAL_INT(0, parse_milestones_confirmed(json_data, res));
  TEST_ASSERT(1139767 == res->index);
  TEST_ASSERT(1637221249 == res->timestamp);

  // clean up
  res_milestones_confirmed_free(res);
}

void process_event_data(event_client_event_t *event) {
  if (!strcmp(event->topic, "milestones/confirmed")) {
    milestone_confirmed_t *res = res_milestones_confirmed_new();
    TEST_ASSERT_NOT_NULL(res);
    TEST_ASSERT_EQUAL_INT(0, parse_milestones_confirmed((char *)event->data, res));
    // Print received data
    printf("Index :%u\nTimestamp : %lu\n", res->index, res->timestamp);
    res_milestones_confirmed_free(res);
  }
}

void callback(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("Node event network error : %s\n", (char *)event->data);
      break;
    case NODE_EVENT_CONNECTED:
      printf("Node event network connected\n");
      /* Making subscriptions in the on_connect()*/
      event_subscribe(event->client, NULL, "milestones/confirmed", 1);
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
      printf("Message arrived\nTopic : %s\n", event->topic);
      process_event_data(event);
      TEST_ASSERT_EQUAL_INT(0, event_stop(event->client));
      break;
    default:
      break;
  }
}

void test_milestones_confirmed_events(void) {
  event_client_config_t config = {
      .host = "mqtt.lb-0.h.chrysalis-devnet.iota.cafe", .port = 1883, .client_id = "iota_test_1", .keepalive = 60};
  event_client_handle_t client = event_init(&config);
  TEST_ASSERT_NOT_NULL(client);
  TEST_ASSERT_EQUAL_INT(0, event_register_cb(client, &callback));
  TEST_ASSERT_EQUAL_INT(0, event_start(client));
  TEST_ASSERT_EQUAL_INT(0, event_destroy(client));
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_milestones_confirmed_parser);
  RUN_TEST(test_milestones_confirmed_events);

  return UNITY_END();
}