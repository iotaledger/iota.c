// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "client/api/events/node_event.h"
#include "client/api/events/sub_messages_metadata.h"
#include "client/api/events/sub_milestone_payload.h"
#include "client/api/events/sub_outputs_payload.h"
#include "client/api/events/sub_serialized_output.h"
#include "client/api/restful/get_message_metadata.h"
#include "client/api/restful/get_output.h"

// Update message id for testing
char const *const test_message_id = "4a0c386d0587a6fda9defb85103e975714e6baeb7cd4d0ab673531057c8ae16e";
char const *const test_transaction_id = "5e753f69b44870aa6a90adf2c366dccac00097c41d5c884dd81ef7cf29eefdd7";
char const *const test_bech32 = "atoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5ymep8aa";
char const *const test_output_id = "5e753f69b44870aa6a90adf2c366dccac00097c41d5c884dd81ef7cf29eefdd70000";
char const *const alias_id = "23dc192ede262b3f4bce379b26c31bad029f62fe";
char const *const nft_id = "efdc112efe262b304bcf379b26c31bad029f61de";
char const *const foundry_id = "56ec192ede262b3f4bce379b26c31bad029f63bc23ef56ee48cf";
char const *const test_tag = "IOTA TEST DATA";

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
      if (event_subscribe(event->client, NULL, TOPIC_MILESTONE_LATEST, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MILESTONE_LATEST);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MILESTONE_CONFIRMED, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MILESTONE_CONFIRMED);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MS_REFERENCED, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MS_REFERENCED);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MILESTONES, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MILESTONES);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MESSAGES, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MESSAGES);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MS_MILESTONE, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MS_MILESTONE);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MS_TRANSACTION, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MS_TRANSACTION);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MS_TXN_TAGGED_DATA, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MS_TXN_TAGGED_DATA);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MS_TAGGED_DATA, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MS_TAGGED_DATA);
      }
      if (event_sub_tx_msg_tagged_data(event->client, NULL, test_tag, 1) != 0) {
        printf("Subscription to %s topic failed\n", "messages/transaction/tagged-data/{tag}");
      }
      if (event_sub_msg_tagged_data(event->client, NULL, test_tag, 1) != 0) {
        printf("Subscription to %s topic failed\n", "messages/tagged-data/{tag}");
      }
      if (event_sub_txn_included_msg(event->client, NULL, test_transaction_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "transactions/{transactionId}/included_message");
      }
      if (event_subscribe_msg_metadata(event->client, NULL, test_message_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "message-metadata/{messageid}");
      }
      if (event_sub_outputs_id(event->client, NULL, test_output_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "outputs/{outputId}");
      }
      if (event_sub_outputs_unlock_address(event->client, NULL, "address", test_bech32, 1) != 0) {
        printf("Subscription to %s topic failed\n", "outputs/unlock/{condition}/{address}");
      }
      if (event_sub_outputs_unlock_address_spent(event->client, NULL, "address", test_bech32, 1) != 0) {
        printf("Subscription to %s topic failed\n", "outputs/unlock/{condition}/{address}/spent");
      }
      if (event_sub_outputs_alias_id(event->client, NULL, alias_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "utputs/aliases/{aliasId}");
      }
      if (event_sub_outputs_nft_id(event->client, NULL, nft_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "outputs/nfts/{nftId}");
      }
      if (event_sub_outputs_foundry_id(event->client, NULL, foundry_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "outputs/foundries/{foundryId}");
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
      printf("Message Received\nTopic : %s\n", event->topic);
      process_event_data(event);
      break;
    default:
      break;
  }
}

static void parse_and_print_message_metadata(event_client_event_t *event) {
  // Create and allocate memory for response object
  msg_meta_t *res = metadata_new();
  if (res) {
    parse_messages_metadata((char *)event->data, res);

    // Print received data
    printf("Msg Id :%s\n", res->msg_id);
    // Get parent id count
    size_t parents_count = msg_meta_parents_count(res);
    for (size_t i = 0; i < parents_count; i++) {
      printf("Parent Id %zu : %s\n", i + 1, msg_meta_parent_get(res, i));
    }
    printf("Inclusion State : %s\n", res->inclusion_state);
    printf("Is Solid : %s\n", res->is_solid ? "true" : "false");
    printf("Should Promote : %s\n", res->should_promote ? "true" : "false");
    printf("Should Reattach : %s\n", res->should_reattach ? "true" : "false");
    printf("Referenced Milestone : %u\n", res->referenced_milestone);

    // Free response object
    metadata_free(res);
  }
}

static void print_serialized_data(unsigned char *data, uint32_t len) {
  printf("Received Serialized Data : ");
  for (uint32_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

static void parse_and_print_output_payload(event_client_event_t *event) {
  get_output_t *output = get_output_new();
  if (output) {
    parse_get_output((char const *const)event->data, output);
    print_get_output(output, 0);
    get_output_free(output);
  }
}

void process_event_data(event_client_event_t *event) {
  // check for topics milestone-info/latest and milestone-info/confirmed
  if (!strcmp(event->topic, TOPIC_MILESTONE_LATEST) || !strcmp(event->topic, TOPIC_MILESTONE_CONFIRMED)) {
    events_milestone_payload_t res = {};
    if (parse_milestone_payload((char *)event->data, &res) == 0) {
      printf("Index :%u\nTimestamp : %u\n", res.index, res.timestamp);
    }
  }
  // check for topic milestones
  else if (!strcmp(event->topic, TOPIC_MILESTONES)) {
    print_serialized_data(event->data, event->data_len);
  }
  // check for topic messages
  else if (!strcmp(event->topic, TOPIC_MESSAGES)) {
    print_serialized_data(event->data, event->data_len);
  }
  // check for topic messages/milestone
  else if (!strcmp(event->topic, TOPIC_MS_MILESTONE)) {
    print_serialized_data(event->data, event->data_len);
  }
  // check for topic messages/transaction
  else if (!strcmp(event->topic, TOPIC_MS_TRANSACTION)) {
    print_serialized_data(event->data, event->data_len);
  }
  // check for topic messages/transaction/tagged-data
  else if (!strcmp(event->topic, TOPIC_MS_TXN_TAGGED_DATA)) {
    print_serialized_data(event->data, event->data_len);
  }
  // check for topic messages/tagged-data
  else if (!strcmp(event->topic, TOPIC_MS_TAGGED_DATA)) {
    print_serialized_data(event->data, event->data_len);
  }
  // check for topics messages/transaction/tagged-data/{tag} and messages/tagged-data/{tag}
  else if (strstr(event->topic, "messages/transaction/tagged-data/") != NULL ||
           strstr(event->topic, "messages/tagged-data/") != NULL) {
    print_serialized_data(event->data, event->data_len);
  }
  // check for topic message-metadata/{messageId} and message-metadata/referenced
  else if (!strcmp(event->topic, "message-metadata/")) {
    parse_and_print_message_metadata(event);
  }
  // check for topic transactions/{transactionId}/included-message
  else if ((strstr(event->topic, "transactions/") != NULL) && (strstr(event->topic, "/included-message") != NULL)) {
    print_serialized_data(event->data, event->data_len);
  }
  /* check for topics :
  1. outputs/{outputId}
  2. outputs/unlock/{condition}/{address}
  3. outputs/unlock/{condition}/{address}/spent
  4. outputs/aliases/{aliasId}
  5. outputs/nfts/{nftId}
  6. outputs/foundries/{foundryId}
  */
  else if (strstr(event->topic, "outputs/") != NULL) {
    parse_and_print_output_payload(event);
  }
}

int main(void) {
  event_client_config_t config = {.host = "localhost", .port = 1883, .client_id = "iota_test_1234", .keepalive = 60};
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
