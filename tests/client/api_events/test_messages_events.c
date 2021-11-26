// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>
#include <time.h>
#include <unity/unity.h>

#include "client/api/events/node_event.h"
#include "client/api/events/sub_messages_metadata.h"
#include "events_test_config.h"

char *message_topic;

bool test_completed = false;

void setUp(void) {}

void tearDown(void) {}

void test_messages_metadata_parser(void) {
  // Sample data for testing
  char *json_data =
      "{\"messageId\":"
      "\"cf5f77d62285b9ed8d617729e9232ae346a328c1897f0939837198e93ec13e85\",\"parentMessageIds\":["
      "\"d026f8b1c856d4e844cc734bbe095429fb880ec4d93f3ccffe3b292a7de17be7\","
      "\"cf5f77d62285b9ed8d617729e9232ae346a328c1897f0939837198e93ec13e85\"],\"isSolid\":true,"
      "\"referencedByMilestoneIndex\":242544,\"ledgerInclusionState\":\"noTransaction\",\"shouldPromote\":true,"
      "\"shouldReattach\":false}";

  // Test for expected events response
  // Create and allocate memory for response object
  msg_metadata_t *res = res_msg_metadata_new();
  TEST_ASSERT_EQUAL_INT(0, parse_messages_metadata(json_data, res));
  TEST_ASSERT_EQUAL_STRING("cf5f77d62285b9ed8d617729e9232ae346a328c1897f0939837198e93ec13e85", res->msg_id);
  TEST_ASSERT((strcmp(res->inclusion_state, "noTransaction") == 0) ||
              (strcmp(res->inclusion_state, "conflicting") == 0) || (strcmp(res->inclusion_state, "included") == 0));
  TEST_ASSERT_TRUE(res->is_solid);
  TEST_ASSERT_TRUE(res->should_promote);
  TEST_ASSERT_FALSE(res->should_reattach);
  TEST_ASSERT_EQUAL_UINT64(242544, res->referenced_milestone);
  // Free response object
  res_msg_metadata_free(res);
}

void process_event_data(event_client_event_t *event) {
  if (!strcmp(event->topic, message_topic)) {
    // Create and allocate memory for response object
    msg_metadata_t *res = res_msg_metadata_new();
    TEST_ASSERT_EQUAL_INT(0, parse_messages_metadata((char *)event->data, res));

    // Print received data
    printf("Msg Id :%s\n", res->msg_id);
    // Get parent id count
    size_t parents_count = res_msg_metadata_parents_len(res);
    for (size_t i = 0; i < parents_count; i++) {
      printf("Parent Id %zu : %s\n", i + 1, res_msg_metadata_parent_get(res, i));
    }
    printf("Inclusion State : %s\n", res->inclusion_state);
    printf("Is Solid : %s\n", res->is_solid ? "true" : "false");
    printf("Should Promote : %s\n", res->should_promote ? "true" : "false");
    printf("Should Reattach : %s\n", res->should_reattach ? "true" : "false");
    printf("Referenced Milestone : %ld\n", res->referenced_milestone);

    // Free response object
    res_msg_metadata_free(res);
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
      event_subscribe(event->client, NULL, message_topic, 1);
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
      // Once event data is received and it is verified, close and destroy event MQTT network
      TEST_ASSERT_EQUAL_INT(0, event_stop(event->client));
      test_completed = true;
      break;
    default:
      break;
  }
}

void test_messages_events() {
  // Event MQTT network config parameters
  event_client_config_t config = {.host = TEST_EVENTS_HOST,
                                  .port = TEST_EVENTS_PORT,
                                  .client_id = TEST_EVENTS_CLIENT_ID,
                                  .keepalive = TEST_EVENTS_KEEP_ALIVE};
  // Create event client
  event_client_handle_t client = event_init(&config);
  TEST_ASSERT_NOT_NULL(client);
  // Register callback
  TEST_ASSERT_EQUAL_INT(0, event_register_cb(client, &callback));

  // Start event client, this is a non blocking call
  TEST_ASSERT_EQUAL_INT(0, event_start(client));
  // Store start time
  time_t start = time(NULL);
  // Calculate time after wait period
  time_t endwait = start + (time_t)TEST_TIMEOUT_SECONDS;
  // Wait until test is completed or timeout reached
  while ((!test_completed) && (start < endwait)) {
    start = time(NULL);
  };

  // Stop event client
  TEST_ASSERT_EQUAL_INT(0, event_destroy(client));

  // Check if test was not completed before timeout
  if (!test_completed) {
    printf("Test Timedout\n");
    TEST_FAIL();
  }
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_messages_metadata_parser);

  /* Test case for messages/referenced topic */
  message_topic = (char *)malloc(strlen(TOPIC_MS_REFERENCED));
  strcpy(message_topic, TOPIC_MS_REFERENCED);
  RUN_TEST(test_messages_events);
  free(message_topic);

  test_completed = false;

  /* Test case for messages/referenced topic */
  message_topic = (char *)malloc(strlen(TOPIC_MSG_ID_META));
  strcpy(message_topic, TOPIC_MSG_ID_META);
  RUN_TEST(test_messages_events);
  free(message_topic);

  return UNITY_END();
}
