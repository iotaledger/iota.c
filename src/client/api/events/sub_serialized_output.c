// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "client/api/events/sub_serialized_output.h"

int event_sub_txn_included_msg(event_client_handle_t client, int *mid, char const transaction_id[], int qos) {
  if ((strlen(transaction_id)) != EVENT_TXN_ID_LEN) {
    printf("[%s:%d]: Transaction id length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // 95 is the max length for string transactions/{transactionId}/included-message
  char topic_buff[95] = {0};

  sprintf(topic_buff, "transactions/%s/included-message", transaction_id);

  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_msg_indexation(event_client_handle_t client, int *mid, char const index[], int qos) {
  if (((strlen(index)) > EVENT_MS_INDEX_MAX_LEN) || ((strlen(index)) < EVENT_MS_INDEX_MIN_LEN)) {
    printf("[%s:%d]: Index length is invalid\n", __func__, __LINE__);
    return -1;
  }
  // 85 is the max length for string messages/indexation/{index}, index max size is 64 bytes
  char topic_buff[85] = {0};

  sprintf(topic_buff, "messages/indexation/%s", index);

  return event_subscribe(client, mid, topic_buff, qos);
}
