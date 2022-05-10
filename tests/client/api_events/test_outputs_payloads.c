// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <time.h>

#include "client/api/events/sub_outputs_payload.h"
#include "client/api/restful/get_output.h"
#include "test_config.h"
#include "unity/unity.h"

bool test_completed = false;
char const *const test_bech32 = "atoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5ymep8aa";
char const *const test_output_id = "5e753f69b44870aa6a90adf2c366dccac00097c41d5c884dd81ef7cf29eefdd70000";
char const *const alias_id = "01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248";
char const *const nft_id = "19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f";
char const *const foundry_id = "56ec192ede262b3f4bce379b26c31bad029f63bc23ef56ee48cf";

void setUp(void) {}

void tearDown(void) {}

static void process_event_data(event_client_event_t *event) {
  get_output_t *output = get_output_new();
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_INT(0, parse_get_output((char const *const)event->data, output));
  print_get_output(output, 0);
  get_output_free(output);
}

static void event_cb(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("Node event network error : %s\n", (char *)event->data);
      break;
    case NODE_EVENT_CONNECTED:
      printf("Node event network connected\n");
      int ret = -1;
      /* Making subscriptions in the on_connect()*/
      // Uncomment for subscribing to respective topics

      ret = event_sub_outputs_id(event->client, NULL, test_output_id, 1);

      /* Allowed values for unlock condition: "address", "storage-return", "expiration", "state-controller", "governor",
       * "immutable-alias", "+" */
      // ret = event_sub_outputs_unlock_address(event->client, NULL, "address", test_bech32, 1);
      // ret = event_sub_outputs_unlock_address_spent(event->client, NULL, "address", test_bech32, 1);

      // ret = event_sub_outputs_alias_id(event->client, NULL, alias_id, 1);
      // ret = event_sub_outputs_nft_id(event->client, NULL, nft_id, 1);
      // ret = event_sub_outputs_foundry_id(event->client, NULL, foundry_id, 1);
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
      // Once event data is received and it is verified, close and destroy event MQTT network
      TEST_ASSERT_EQUAL_INT(0, event_stop(event->client));
      test_completed = true;
      break;
    default:
      break;
  }
}

void event_get_output(void) {
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
  RUN_TEST(event_get_output);
#endif

  return UNITY_END();
}
