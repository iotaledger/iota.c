// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>

#include "client/api/events/sub_blocks_metadata.h"
#include "client/api/json_parser/json_utils.h"
#include "client/constants.h"
#include "client/network/mqtt/mqtt.h"

int event_subscribe_blk_metadata(event_client_handle_t client, int *mid, char const msg_id[], int qos) {
  if (strlen(msg_id) != BIN_TO_HEX_BYTES(IOTA_BLOCK_ID_BYTES)) {
    printf("[%s:%d]: Message Id length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // Buffer to store topic string : block-metadata/0x{blockid}
  char topic_buff[BIN_TO_HEX_BYTES(IOTA_BLOCK_ID_BYTES) + 20] = {0};
  // Prepare topic string
  sprintf(topic_buff, "block-metadata/0x%s", msg_id);
  // Call to MQTT network layer
  return event_subscribe(client, mid, topic_buff, qos);
}
