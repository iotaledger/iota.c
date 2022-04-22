// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a data to the Tangle.
 *
 */

#include <stdio.h>
#include <string.h>

#include "client/api/restful/get_message.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/iota_str.h"

#define TAG "iota.c\xF0\x9F\xA6\x8B"
#define MESSAGE "Hello world"

int main(void) {
  iota_client_conf_t ctx = {.host = "localhost", .port = 443, .use_tls = true};

  res_send_message_t res = {};

  // send Hello world to the Tangle
  printf("Sending data message to the Tangle...\n");
  if (send_tagged_data_message(&ctx, 2, (byte_t *)TAG, strlen(TAG), (byte_t *)MESSAGE, strlen(MESSAGE), &res) == 0) {
    if (res.is_error) {
      printf("API response: %s\n", res.u.error->msg);
      return -1;
    }
  } else {
    printf("Sending message failed!\n");
    return -1;
  }

  printf("Message successfully sent.\n");
  printf("Message ID: %s\n", res.u.msg_id);

  res_message_t *msg = res_message_new();
  if (!msg) {
    printf("Failed to create a response message object!\n");
    return -1;
  }

  // fetch message from the Tangle
  printf("Fetching message from the Tangle...\n");
  if (get_message_by_id(&ctx, res.u.msg_id, msg) == 0) {
    if (msg->is_error) {
      printf("API response: %s\n", msg->u.error->msg);
      res_message_free(msg);
      return -1;
    }
  } else {
    printf("Fetching message from a node failed!\n");
    res_message_free(msg);
    return -1;
  }

  printf("Message successfully fetched.\n");

  // check if fetched message is Tagged Data message
  if (msg->u.msg->payload_type != CORE_MESSAGE_PAYLOAD_TAGGED) {
    printf("Fetched message is not a Tagged Data message!\n");
    res_message_free(msg);
    return -1;
  }

  // print fetched message
  iota_str_t *tag = iota_str_new("");
  iota_str_appendn(tag, (char const *)((tagged_data_payload_t *)msg->u.msg->payload)->tag->data,
                   ((tagged_data_payload_t *)msg->u.msg->payload)->tag->len);
  iota_str_t *data = iota_str_new("");
  iota_str_appendn(data, (char const *)((tagged_data_payload_t *)msg->u.msg->payload)->data->data,
                   ((tagged_data_payload_t *)msg->u.msg->payload)->data->len);

  printf("Tagged Data:\n");
  printf("\tTag: %s\n", tag->buf);
  printf("\tData: %s\n", data->buf);

  // clean up resources
  iota_str_destroy(tag);
  iota_str_destroy(data);
  res_message_free(msg);

  return 0;
}
