// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "client/api/events/sub_serialized_output.h"
#include "core/address.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/macros.h"

int event_sub_txn_included_blk(event_client_handle_t client, int *mid, char const transaction_id[], int qos) {
  if (strlen(transaction_id) != BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES)) {
    printf("[%s:%d]: Transaction id length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // buffer for holding string "transactions/0x{transactionId}/included-block"
  char topic_buff[31 + BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES)] = {0};

  sprintf(topic_buff, "transactions/0x%s/included-block", transaction_id);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_tx_blk_tagged_data(event_client_handle_t client, int *mid, byte_t tag[], uint8_t tag_len, int qos) {
  if (tag_len > TAGGED_DATA_TAG_MAX_LENGTH_BYTES) {
    printf("[%s:%d]: Tag length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // 34 is the max length for string blocks/transaction/tagged-data/0x, max hex-encoded-tag is 128
  char topic_buff[34 + BIN_TO_HEX_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES)] = {0};

  // hex encoded tag string
  char tag_str[BIN_TO_HEX_STR_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES)] = {0};
  if (bin_2_hex(tag, tag_len, NULL, tag_str, sizeof(tag_str)) != 0) {
    printf("[%s:%d] bin to hex tag conversion failed\n", __func__, __LINE__);
    return -1;
  }

  sprintf(topic_buff, "blocks/transaction/tagged-data/0x%s", tag_str);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_blk_tagged_data(event_client_handle_t client, int *mid, byte_t tag[], uint8_t tag_len, int qos) {
  if (tag_len > TAGGED_DATA_TAG_MAX_LENGTH_BYTES) {
    printf("[%s:%d]: Tag length is invalid\n", __func__, __LINE__);
    return -1;
  }

  // hex encoded tag string
  char tag_str[BIN_TO_HEX_STR_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES)] = {0};
  if (bin_2_hex(tag, tag_len, NULL, tag_str, sizeof(tag_str)) != 0) {
    printf("[%s:%d] bin to hex tag conversion failed\n", __func__, __LINE__);
    return -1;
  }

  // 22 is the max length for string blocks/tagged-data/0x, max hex-encoded-tag is 128
  char topic_buff[22 + BIN_TO_HEX_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES)] = {0};
  sprintf(topic_buff, "%s/0x%s", TOPIC_BLK_TAGGED_DATA, tag_str);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_unsub_blk_tagged_data(event_client_handle_t client, int *mid, byte_t tag[], uint8_t tag_len) {
  if (tag_len > TAGGED_DATA_TAG_MAX_LENGTH_BYTES) {
    printf("[%s:%d]: Tag length is invalid\n", __func__, __LINE__);
    return -1;
  }

  // hex encoded tag string
  char tag_str[BIN_TO_HEX_STR_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES)] = {0};
  if (bin_2_hex(tag, tag_len, NULL, tag_str, sizeof(tag_str)) != 0) {
    printf("[%s:%d] bin to hex tag conversion failed\n", __func__, __LINE__);
    return -1;
  }

  // 22 is the max length for string blocks/tagged-data/0x, max hex-encoded-tag is 128
  char topic_buff[22 + BIN_TO_HEX_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES)] = {0};
  sprintf(topic_buff, "%s/0x%s", TOPIC_BLK_TAGGED_DATA, tag_str);

  return event_unsubscribe(client, mid, topic_buff);
}
