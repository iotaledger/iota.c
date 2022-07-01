// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "client/api/events/node_event.h"
#include "client/api/events/sub_blocks_metadata.h"
#include "client/api/events/sub_milestone_payload.h"
#include "client/api/events/sub_outputs_payload.h"
#include "client/api/events/sub_serialized_output.h"
#include "client/api/restful/get_block_metadata.h"
#include "client/api/restful/get_output.h"
#include "core/models/payloads/tagged_data.h"

// Update block id for testing
char const *const test_block_id = "4a0c386d0587a6fda9defb85103e975714e6baeb7cd4d0ab673531057c8ae16e";
char const *const test_transaction_id = "5e753f69b44870aa6a90adf2c366dccac00097c41d5c884dd81ef7cf29eefdd7";
char const *const test_bech32 = "atoi1qqs7y6ec5vcg6cnz46vjrar2epc52lhksyar3a4zua7fg7ca08y5ymep8aa";
char const *const test_output_id = "5e753f69b44870aa6a90adf2c366dccac00097c41d5c884dd81ef7cf29eefdd70000";
char const *const alias_id = "01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248";
char const *const nft_id = "19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f";
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
      if (event_subscribe(event->client, NULL, TOPIC_BLOCK_REFERENCED, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_BLOCK_REFERENCED);
      }
      if (event_subscribe(event->client, NULL, TOPIC_MILESTONES, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_MILESTONES);
      }
      if (event_subscribe(event->client, NULL, TOPIC_BLOCKS, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_BLOCKS);
      }
      if (event_subscribe(event->client, NULL, TOPIC_BLK_TRANSACTION, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_BLK_TRANSACTION);
      }
      if (event_subscribe(event->client, NULL, TOPIC_BLK_TXN_TAGGED_DATA, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_BLK_TXN_TAGGED_DATA);
      }
      if (event_subscribe(event->client, NULL, TOPIC_BLK_TAGGED_DATA, 1) != 0) {
        printf("Subscription to %s topic failed\n", TOPIC_BLK_TAGGED_DATA);
      }
      if (event_sub_tx_blk_tagged_data(event->client, NULL, (byte_t *)test_tag, strlen(test_tag), 1) != 0) {
        printf("Subscription to %s topic failed\n", "blocks/transaction/tagged-data/{tag}");
      }
      if (event_sub_blk_tagged_data(event->client, NULL, (byte_t *)test_tag, strlen(test_tag), 1) != 0) {
        printf("Subscription to %s topic failed\n", "blocks/tagged-data/{tag}");
      }
      if (event_sub_txn_included_blk(event->client, NULL, test_transaction_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "transactions/{transactionId}/included_block");
      }
      if (event_subscribe_blk_metadata(event->client, NULL, test_block_id, 1) != 0) {
        printf("Subscription to %s topic failed\n", "block-metadata/{blockid}");
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
        printf("Subscription to %s topic failed\n", "outputs/aliases/{aliasId}");
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

static void parse_and_print_block_metadata(event_client_event_t *event) {
  // Create and allocate memory for response object
  block_meta_t *res = metadata_new();
  if (res) {
    parse_blocks_metadata((char *)event->data, res);

    // Print received data
    printf("Msg Id :%s\n", res->blk_id);
    // Get parent id count
    size_t parents_count = block_meta_parents_count(res);
    for (size_t i = 0; i < parents_count; i++) {
      printf("Parent Id %zu : %s\n", i + 1, block_meta_parent_get(res, i));
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

static void print_serialized_block(unsigned char *data, uint32_t len) {
  core_block_t *b = core_block_deserialize(data, len);
  if (b) {
    core_block_print(b, 0);
    if (b->payload_type == CORE_BLOCK_PAYLOAD_TAGGED) {
      tagged_data_payload_t *t = (tagged_data_payload_t *)b->payload;
      printf("Tag: %.*s\n", (int)t->tag->len, t->tag->data);
      printf("Data: %.*s\n", (int)t->data->len, t->data->data);
    }
    core_block_free(b);
  } else {
    printf("decode block failed\n");
  }
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
    events_milestone_payload_t res = {0};
    if (parse_milestone_payload((char *)event->data, &res) == 0) {
      printf("Index :%u\nTimestamp : %u\n", res.index, res.timestamp);
    }
  }
  // check for topic milestones
  else if (!strcmp(event->topic, TOPIC_MILESTONES)) {
    // TODO: milestone deserialization
    print_serialized_data(event->data, event->data_len);
  }
  // check for topic blocks
  else if (!strcmp(event->topic, TOPIC_BLOCKS)) {
    print_serialized_block(event->data, event->data_len);
  }
  // check for topic blocks/transaction
  else if (!strcmp(event->topic, TOPIC_BLK_TRANSACTION)) {
    print_serialized_block(event->data, event->data_len);
  }
  // check for topic blocks/transaction/tagged-data
  else if (!strcmp(event->topic, TOPIC_BLK_TXN_TAGGED_DATA)) {
    print_serialized_block(event->data, event->data_len);
  }
  // check for topic blocks/tagged-data
  else if (!strcmp(event->topic, TOPIC_BLK_TAGGED_DATA)) {
    print_serialized_block(event->data, event->data_len);
  }
  // check for topics blocks/transaction/tagged-data/{tag} and blocks/tagged-data/{tag}
  else if (strstr(event->topic, "blocks/transaction/tagged-data/") != NULL ||
           strstr(event->topic, "blocks/tagged-data/") != NULL) {
    print_serialized_block(event->data, event->data_len);
  }
  // check for topic block-metadata/{blockId} and block-metadata/referenced
  else if (!strcmp(event->topic, "block-metadata/")) {
    parse_and_print_block_metadata(event);
  }
  // check for topic transactions/{transactionId}/included-block
  else if ((strstr(event->topic, "transactions/") != NULL) && (strstr(event->topic, "/included-block") != NULL)) {
    print_serialized_block(event->data, event->data_len);
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
  // Blocking main loop, callbacks will be processed on event arrival
  while (!is_error) {
  };
  // Stop event client instance
  event_stop(client);
  // Destroy event client instance
  event_destroy(client);
  return 0;
}
