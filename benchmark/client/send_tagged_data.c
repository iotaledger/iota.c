// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/restful/get_node_info.h"
#include "client/api/restful/send_tagged_data.h"

#define NODE_HOST "api.alphanet.iotaledger.net"
#define NODE_PORT 443
#define IS_HTTPS true

int main() {
  iota_client_conf_t ctx = {.host = NODE_HOST, .port = NODE_PORT, .use_tls = IS_HTTPS};

  res_node_info_t* info = res_node_info_new();
  if (!info) {
    printf("[%s:%d]: Can not create node info object!\n", __func__, __LINE__);
    return -1;
  }

  int result = get_node_info(&ctx, info);
  if (result != 0 || info->is_error || info->u.output_node_info == NULL) {
    printf("[%s:%d]: Can not received node info data!\n", __func__, __LINE__);
    res_node_info_free(info);
    return -1;
  }

  byte_t tag[] = "Test tag from a benchmark application.";
  byte_t tag_data[] = "Test tagged data from a benchmark application";
  res_send_message_t res = {};

  result = send_tagged_data_message(&ctx, info->u.output_node_info->protocol_version, tag, sizeof(tag), tag_data,
                                    sizeof(tag_data), &res);
  if (result != 0 || res.is_error) {
    printf("[%s:%d]: Can not send tagged data message!\n", __func__, __LINE__);
    res_node_info_free(info);
    return -1;
  }
  res_node_info_free(info);

  printf("[%s:%d]: Message successfully send! URL: https://%s/api/v2/messages/0x%s\n", __func__, __LINE__, NODE_HOST,
         res.u.msg_id);

  return 0;
}
