// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of getting a message by its ID from the Tangle.
 *
 */

#include <stdio.h>

#include "client/api/restful/get_message.h"

// replace this message ID as needed
// Milestone
#define MSG_ID "c0192ab155b501d2b51d4342b32970360d03835cce84f3b5a8c58e5f0c403b57"
// Tagged Data
//#define MSG_ID "6fc54c980a7a7480d4cb029c64e9a73eb1d4c3a1df40a297b607e1e137322142"
// Transaction
//#define MSG_ID "e95846e997dc6dae80e9a6dea908577a167b5e7c53b9fd802a760486a8c90d0f"

int main(void) {
  iota_client_conf_t ctx = {.host = "localhost", .port = 443, .use_tls = true};

  res_message_t *msg = res_message_new();
  if (!msg) {
    printf("Failed to create a response message object!\n");
    return -1;
  }

  if (get_message_by_id(&ctx, (char const *)MSG_ID, msg) != 0) {
    printf("Retrieving message from a node failed!\n");
    res_message_free(msg);
    return -1;
  }

  if (msg->is_error) {
    printf("API response: %s\n", msg->u.error->msg);
    res_message_free(msg);
    return -1;
  }

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
      printf("Unsupported type of a message received!\n");
      break;
  }

  res_message_free(msg);

  return 0;
}
