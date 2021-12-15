// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "client/api/events/node_event.h"
#include "client/api/events/sub_messages_metadata.h"
#include "client/api/events/sub_milestone_latest.h"
#include "client/api/events/sub_milestones_confirmed.h"
#include "client/api/events/sub_outputs_payload.h"
#include "client/api/events/sub_serialized_output.h"

// Update message id for testing
char const *const test_message_id = "406d0d18ee7cd35e80465b61d1a90842bfa49012392057f65c22d7d4eb7768c7";
char const *const test_output_id = "3912942d1cb588d8091eff2069bdd797a0a834739dc8ea550e35fb0dc8609c820000";
char const *const test_bech32 = "atoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5ymep8aa";
char const *const test_ed25519 = "21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942";
char const *const test_transaction_id = "963b96adc39ebb7f96cfc523a4b4df658c2fb4a1bb5a9f0de5fa66e7207a2236";
char const *const test_index = "546573746e6574205370616d6d6572";

bool is_error = false;

void process_event_data(event_client_event_t *event);

void callback(event_client_event_t *event) {
  switch (event->event_id) {
    case NODE_EVENT_ERROR:
      printf("Node event network error : %s\n", (char *)event->data);
      is_error = true;
      break;
    case NODE_EVENT_CONNECTED:
      printf("Node event network connected\n");
      /* Making subscriptions in the on_connect() callback means that if the
       * connection drops and is automatically resumed by the client, then the
       * subscriptions will be recreated when the client reconnects. */
      event_subscribe(event->client, NULL, TOPIC_MS_LATEST, 1);
      event_subscribe(event->client, NULL, TOPIC_MS_CONFIRMED, 1);
      event_subscribe(event->client, NULL, TOPIC_MS_REFERENCED, 1);
      event_subscribe(event->client, NULL, TOPIC_MESSAGES, 1);
      event_subscribe_msg_metadata(event->client, NULL, test_message_id, 1);
      event_sub_address_outputs(event->client, NULL, test_bech32, true, 1);
      event_sub_address_outputs(event->client, NULL, test_ed25519, false, 1);
      event_sub_outputs_id(event->client, NULL, test_output_id, 1);
      event_sub_txn_included_msg(event->client, NULL, test_transaction_id, 1);
      event_sub_msg_indexation(event->client, NULL, test_index, 1);
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

void parse_and_print_message_metadata(char *data) {
  msg_metadata_t *res = res_msg_metadata_new();
  if (res) {
    if (parse_messages_metadata(data, res) == 0) {
      printf("Msg Id :%s\n", res->msg_id);
      size_t parents_count = res_msg_metadata_parents_count(res);
      for (size_t i = 0; i < parents_count; i++) {
        printf("Parent Id %zu : %s\n", i + 1, res_msg_metadata_parent_get(res, i));
      }
      printf("Inclusion State : %s\n", res->inclusion_state);
      printf("Is Solid : %s\n", res->is_solid ? "true" : "false");
      printf("Should Promote : %s\n", res->should_promote ? "true" : "false");
      printf("Should Reattach : %s\n", res->should_reattach ? "true" : "false");
      printf("Referenced Milestone : %ld\n", res->referenced_milestone);
    }
    res_msg_metadata_free(res);
  } else {
    is_error = true;
  }
}

void parse_and_print_output_payload(char *data) {
  event_outputs_payload_t res = {};
  event_parse_outputs_payload(data, &res);
  printf("Message ID: %s\n", res.msg_id);
  printf("Transaction ID: %s\n", res.tx_id);
  printf("Output Index: %d\n", res.output_index);
  printf("Ledger Index: %" PRIu64 "\n", res.ledger_index);
  printf("isSpent: %s\n", res.is_spent ? "True" : "False");
  printf("Addr: %s\n", res.output.addr);
  printf("Amount: %" PRIu64 "\n", res.output.amount);
}

void print_serialized_data(unsigned char *data, uint32_t len) {
  printf("Received Serialized Data : ");
  for (uint32_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

void process_event_data(event_client_event_t *event) {
  if (!strcmp(event->topic, TOPIC_MS_LATEST)) {
    milestone_latest_t res = {};
    if (parse_milestone_latest((char *)event->data, &res) == 0) {
      printf("Index :%u\nTimestamp : %lu\n", res.index, res.timestamp);
    }
  } else if (!strcmp(event->topic, TOPIC_MS_CONFIRMED)) {
    milestone_confirmed_t res = {};
    if (parse_milestones_confirmed((char *)event->data, &res) == 0) {
      printf("Index :%u\nTimestamp : %lu\n", res.index, res.timestamp);
    }
  } else if (!strcmp(event->topic, TOPIC_MS_REFERENCED)) {
    parse_and_print_message_metadata(event->data);
  } else if (!strcmp(event->topic, TOPIC_MESSAGES)) {
    print_serialized_data(event->data, event->data_len);
  } else if ((strstr(event->topic, "messages/") != NULL) && (strstr(event->topic, "/metadata") != NULL)) {
    parse_and_print_message_metadata(event->data);
  } else if ((strstr(event->topic, "outputs/") != NULL)) {
    parse_and_print_output_payload(event->data);
  } else if ((strstr(event->topic, "addresses/") != NULL)) {
    parse_and_print_output_payload(event->data);
  } else if ((strstr(event->topic, "transactions/") != NULL) && (strstr(event->topic, "/included-message") != NULL)) {
    print_serialized_data(event->data, event->data_len);
  } else if (strstr(event->topic, "messages/indexation/")) {
    print_serialized_data(event->data, event->data_len);
  }
}

int main(void) {
  event_client_config_t config = {
      .host = "mqtt.lb-0.h.chrysalis-devnet.iota.cafe", .port = 1883, .client_id = "iota_test_1234", .keepalive = 60};
  event_client_handle_t client = event_init(&config);
  event_register_cb(client, &callback);
  // Runs event client in a non blocking call.
  event_start(client);
  // Blocking main loop, callbacks will be processed on event message arrival
  while (!is_error) {
  };
  // Stop event client instance
  event_stop(client);
  // Destroy event client instance
  event_destroy(client);
  return 0;
}
