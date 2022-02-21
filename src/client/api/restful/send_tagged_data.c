// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/send_tagged_data.h"
#include "core/models/message.h"
#include "core/models/payloads/tagged_data.h"

int send_tagged_data_message(iota_client_conf_t const* conf, char const tag[], byte_t data[], uint32_t data_len,
                             res_send_message_t* res) {
  if (conf == NULL || res == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  // Create tagged data payload
  tagged_data_t* tagged_data = tagged_data_create(tag, data, data_len);
  if (tagged_data == NULL) {
    return -1;
  }

  // Create a core message object
  core_message_t* msg = core_message_new();
  if (!msg) {
    printf("[%s:%d] core message allocation failed\n", __func__, __LINE__);
    return -1;
  }
  msg->network_id = 0;
  msg->payload_type = CORE_MESSAGE_PAYLOAD_TAGGED;
  msg->payload = tagged_data;
  msg->nonce = 0;

  int ret = send_core_message(conf, msg, res);
  core_message_free(msg);
  return ret;
}
