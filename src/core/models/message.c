// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "core/models/message.h"

core_message_t* core_message_new() {
  core_message_t* msg = malloc(sizeof(core_message_t));
  if (msg) {
    msg->network_id = 0;
    memset(msg->parent1, 0, sizeof(msg->parent1));
    memset(msg->parent2, 0, sizeof(msg->parent2));
    msg->payload_type = UINT32_MAX - 1;  // invalid payload type
    msg->payload = NULL;
    msg->nonce = 0;
  }
  return msg;
}

void core_message_free(core_message_t* msg) {
  if (msg) {
    if (msg->payload) {
      if (msg->payload_type == 0) {
        tx_payload_free((transaction_payload_t*)msg->payload);
      }
      if (msg->payload_type == 2) {
        indexation_free((indexation_t*)msg->payload);
      }
      // TODO support other payload
    }
    free(msg);
  }
}