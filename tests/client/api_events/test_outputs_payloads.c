// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <time.h>

#include "client/api/events/sub_outputs_payload.h"
#include "events_test_config.h"
#include "unity/unity.h"

bool test_completed = false;
char const *const test_bech32 = "atoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5ymep8aa";
char const *const test_ed25519 = "21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942";
char const *const test_output_id = "3912942d1cb588d8091eff2069bdd797a0a834739dc8ea550e35fb0dc8609c820000";

void setUp(void) {}

void tearDown(void) {}

void address_outputs_parser() {
  char const *const data =
      "{\"messageId\":\"286efdc4c4769dd4672b8c42cbb0c05dfe1b07f8e3e5572f905de6051ef50fc3\",\"transactionId\":"
      "\"fff6ddfc16b67cf01661c98d15caa2aa8c1e3bbc771e94e7cd1a4b2c792ebc43\",\"outputIndex\":0,\"isSpent\":false,"
      "\"ledgerIndex\":1231739,\"output\":{\"type\":0,\"address\":{\"type\":0,\"address\":"
      "\"21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942\"},\"amount\":1000000}}";

  event_addr_outputs_t res = {};

  TEST_ASSERT(event_parse_address_outputs(data, &res) == 0);
  TEST_ASSERT_EQUAL_STRING("286efdc4c4769dd4672b8c42cbb0c05dfe1b07f8e3e5572f905de6051ef50fc3", res.msg_id);
  TEST_ASSERT_EQUAL_STRING("fff6ddfc16b67cf01661c98d15caa2aa8c1e3bbc771e94e7cd1a4b2c792ebc43", res.tx_id);
  TEST_ASSERT(res.output_index == 0);
  TEST_ASSERT(res.ledger_index == 1231739);
  TEST_ASSERT_FALSE(res.is_spent);

  // validating output object
  TEST_ASSERT(res.output.output_type == 0);
  TEST_ASSERT_EQUAL_STRING("21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942", res.output.addr);
  TEST_ASSERT(res.output.amount == 1000000);
}

static void dump_event_data(event_client_event_t *event) {
  event_addr_outputs_t res = {};
  event_parse_address_outputs(event->data, &res);
  printf("Message ID: %s\n", res.msg_id);
  printf("Transaction ID: %s\n", res.tx_id);
  printf("Output Index: %d\n", res.output_index);
  printf("Ledger Index: %" PRIu64 "\n", res.ledger_index);
  printf("isSpent: %s\n", res.is_spent ? "True" : "False");
  printf("ED25519 addr: %s\n", res.output.addr);
  printf("Amount: %" PRIu64 "\n", res.output.amount);
}

static void event_cb(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("Node event network error : %s\n", (char *)event->data);
      break;
    case NODE_EVENT_CONNECTED:
      printf("Node event network connected\n");
      /* Making subscriptions in the on_connect()*/
      event_sub_address_outputs(event->client, NULL, test_bech32, true, 1);
      // event_sub_address_outputs(event->client, NULL, test_ed25519, false, 1);
      // event_sub_outputs_id(event->client, NULL, test_output_id, 1);
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
      dump_event_data(event);
      // Once event data is received and it is verified, close and destroy event MQTT network
      TEST_ASSERT_EQUAL_INT(0, event_stop(event->client));
      test_completed = true;
      break;
    default:
      break;
  }
}

void event_address_outputs(void) {
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

  RUN_TEST(address_outputs_parser);

  // for local test only
  // RUN_TEST(event_address_outputs);

  return UNITY_END();
}
