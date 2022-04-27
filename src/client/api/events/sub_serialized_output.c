// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "client/api/events/sub_serialized_output.h"
#include "core/address.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/macros.h"

int event_sub_txn_included_msg(event_client_handle_t client, int *mid, char const transaction_id[], int qos) {
  if (strlen(transaction_id) != BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES)) {
    printf("[%s:%d]: Transaction id length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // 95 is the max length for string transactions/{transactionId}/included-message
  char topic_buff[97] = {0};

  sprintf(topic_buff, "transactions/0x%s/included-message", transaction_id);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_tx_msg_tagged_data(event_client_handle_t client, int *mid, char const tag[], int qos) {
  if (strlen(tag) > TAGGED_DATA_TAG_MAX_LENGTH_BYTES) {
    printf("[%s:%d]: Tag length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // 100 is the max length for string messages/transaction/tagged-data/0x{tag}, tag max len is 64 bytes
  char topic_buff[100] = {0};

  sprintf(topic_buff, "messages/transaction/tagged-data/0x%s", tag);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_msg_tagged_data(event_client_handle_t client, int *mid, char const tag[], int qos) {
  if (strlen(tag) > TAGGED_DATA_TAG_MAX_LENGTH_BYTES) {
    printf("[%s:%d]: Tag length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // 88 is the max length for string messages/tagged-data/0x{tag}, tag max len is 64 bytes
  char topic_buff[88] = {0};

  sprintf(topic_buff, "messages/tagged-data/0x%s", tag);

  return event_subscribe(client, mid, topic_buff, qos);
}
