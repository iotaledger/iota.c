// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>

#include "client/api/events/sub_messages_metadata.h"
#include "client/api/json_parser/json_utils.h"
#include "client/network/mqtt/mqtt.h"

int event_subscribe_msg_metadata(event_client_handle_t client, int *mid, char const msg_id[], int qos) {
  if ((strlen(msg_id)) != MSG_ID_LEN) {
    printf("[%s:%d]: Message Id length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // Buffer to store topic string : messages/{messageid}/metadata
  char topic_buff[MSG_ID_LEN + 21] = {0};
  // Prepare topic string
  sprintf(topic_buff, "messages/0x%s/metadata", msg_id);
  // Call to MQTT network layer
  return event_subscribe(client, mid, topic_buff, qos);
}