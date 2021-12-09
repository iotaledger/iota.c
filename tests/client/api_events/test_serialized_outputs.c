// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <time.h>

#include "client/api/events/sub_serialized_output.h"
#include "test_config.h"
#include "unity/unity.h"

bool test_completed = false;
char const *const test_transaction_id = "963b96adc39ebb7f96cfc523a4b4df658c2fb4a1bb5a9f0de5fa66e7207a2236";
char const *const test_index = "546573746e6574205370616d6d6572";

void setUp(void) {}

void tearDown(void) {}

static void dump_serialized_output(unsigned char *data, uint32_t len) {
  printf("Received Serialized Data : ");
  for (uint32_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

static void event_cb(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("Node event network error : %s\n", (char *)event->data);
      break;
    case NODE_EVENT_CONNECTED:
      printf("Node event network connected\n");
      /* Making subscriptions in the on_connect()*/
      // Uncomment for subscribing to respective topics
      event_subscribe(event->client, NULL, TOPIC_MESSAGES, 1);
      // event_sub_txn_included_msg(event->client, NULL, test_transaction_id, 1);
      // event_sub_msg_indexation(event->client, NULL, test_index, 1);
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
      dump_serialized_output(event->data, event->data_len);
      // Once event data is received and it is verified, close and destroy event MQTT network
      TEST_ASSERT_EQUAL_INT(0, event_stop(event->client));
      test_completed = true;
      break;
    default:
      break;
  }
}

void event_serialized_outputs(void) {
  // Event MQTT network config parameters
  event_client_config_t config = {.host = TEST_EVENTS_HOST,
                                  .port = TEST_EVENTS_PORT,
                                  .client_id = TEST_EVENTS_CLIENT_ID,
                                  .keepalive = TEST_EVENTS_KEEP_ALIVE};
  // Create event client
  event_client_handle_t client = event_init(&config);
  TEST_ASSERT_NOT_NULL(client);
  // Register callback
  TEST_ASSERT_EQUAL_INT(0, event_register_cb(client, &event_cb));
  // Start event client, this is a blocking call
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

#if TEST_TANGLE_ENABLE
  RUN_TEST(event_serialized_outputs);
#endif

  return UNITY_END();
}
