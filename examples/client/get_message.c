// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of getting a message by its ID from the Tangle.
 *
 */

#include <stdio.h>

#include "client/api/restful/get_message.h"

int main(void) {
  // replace this message id as needed
  // Milestone
  char const *const msg_id = "c7217f10fbeabd96afc22cf8b058c4ccc9d2b1fe2b393091b7bda629c3afe222";
  // Tagged Data
  // char const* const msg_id = "3ac16fe3ff82c89dcf02fc5fecb374077c4e6ee6a6f71309dc57f1e0bc245c6c";
  // Transaction
  // char const *const msg_id = "f408260482edcb67ef79a679d6a143a36cc5ffb4c4e11c209f0c5654b34bedc4";

  iota_client_conf_t ctx = {.host = "localhost", .port = 443, .use_tls = true};

  res_message_t *msg = res_message_new();
  if (msg) {
    if (get_message_by_id(&ctx, msg_id, msg) == 0) {
      if (msg->is_error) {
        printf("API response: %s\n", msg->u.error->msg);
      } else {
        switch (msg->u.msg->payload_type) {
          case CORE_MESSAGE_PAYLOAD_MILESTONE:
            printf("Milestone message received:\n");
            core_message_print(msg->u.msg, 0);
            break;
          case CORE_MESSAGE_PAYLOAD_TAGGED:
            printf("Tagged Data message received:\n");
            core_message_print(msg->u.msg, 0);
            break;
          case CORE_MESSAGE_PAYLOAD_TRANSACTION:
            printf("Transaction message received:\n");
            core_message_print(msg->u.msg, 0);
            break;
          default:
            printf("Unsupported message type!\n");
            break;
        }
      }
    } else {
      printf("Retrieving message from a node failed!\n");
    }
    res_message_free(msg);
  } else {
    printf("Failed to create a response message object!\n");
  }

  return 0;
}
