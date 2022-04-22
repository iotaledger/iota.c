// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>
#include <time.h>
#include <unity/unity.h>

#include "client/api/events/node_event.h"
#include "client/api/events/sub_milestone_payload.h"
#include "test_config.h"

bool test_completed = false;

void setUp(void) {}

void tearDown(void) {}

void test_milestones_payload_parser(void) {
  char *json_data = "{\"index\":242412,\"timestamp\": 1609950538}";

  // Test for expected events response
  events_milestone_payload_t res = {};
  TEST_ASSERT_EQUAL_INT(0, parse_milestone_payload(json_data, &res));
  TEST_ASSERT(242412 == res.index);
  TEST_ASSERT(1609950538 == res.timestamp);
}

void process_event_data(event_client_event_t *event) {
  if (!strcmp(event->topic, TOPIC_MS_LATEST)) {
    events_milestone_payload_t res = {};
    TEST_ASSERT_EQUAL_INT(0, parse_milestone_payload((char *)event->data, &res));
    // Print received data
    printf("Index :%u\nTimestamp : %u\n", res.index, res.timestamp);
  }
}

void callback(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("Node event network error : %s\n", (char *)event->data);
      break;
    case NODE_EVENT_CONNECTED:
      printf("Node event network connected\n");
      int ret = -1;
      /* Making subscriptions in the on_connect()*/
      // Uncomment for subscribing to respective topics
      ret = event_subscribe(event->client, NULL, TOPIC_MS_LATEST, 1);
      // ret = event_subscribe(event->client, NULL, TOPIC_MS_CONFIRMED, 1);
      if (ret != 0) {
        printf("Subscription failed\n");
        test_completed = true;
      }
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
      test_completed = true;
      break;
    default:
      break;
  }
}

void test_milestone_events(void) {
  event_client_config_t config = {.host = TEST_EVENTS_HOST,
                                  .port = TEST_EVENTS_PORT,
                                  .client_id = TEST_EVENTS_CLIENT_ID,
                                  .keepalive = TEST_EVENTS_KEEP_ALIVE};
  event_client_handle_t client = event_init(&config);
  TEST_ASSERT_NOT_NULL(client);
  TEST_ASSERT_EQUAL_INT(0, event_register_cb(client, &callback));
  TEST_ASSERT_EQUAL_INT(0, event_start(client));
  // Store start time
  time_t start = time(NULL);
  // Calculate time after wait period
  time_t endwait = start + (time_t)TEST_TIMEOUT_SECONDS;
  // Wait until test is completed or timeout reached
  while ((!test_completed) && (start < endwait)) {
    start = time(NULL);
  };
  // Destroy event client
  TEST_ASSERT_EQUAL_INT(0, event_destroy(client));
  // Check if test was not completed before timeout
  if (!test_completed) {
    printf("Test Timedout\n");
    TEST_FAIL();
  }
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_milestones_payload_parser);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_milestone_events);
#endif

  return UNITY_END();
}
