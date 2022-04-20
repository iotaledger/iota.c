// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <mcheck.h>
#include <stdio.h>

#include "benchmark_config.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/models/outputs/feat_blocks.h"

int main() {
  // enable memory tracing
  mtrace();

  iota_client_conf_t ctx = {.host = NODE_HOST, .port = NODE_PORT, .use_tls = false};

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

  byte_t tag[MAX_INDEX_TAG_BYTES] = "Test tagged data from a benchmark application. Test tagged dat";
  byte_t* tag_data = malloc(MAX_METADATA_LENGTH_BYTES);
  if (!tag_data) {
    printf("[%s:%d]: Can not create tag data object!\n", __func__, __LINE__);
    res_node_info_free(info);
    return -1;
  }
  res_send_message_t res = {};

  result = send_tagged_data_message(&ctx, info->u.output_node_info->protocol_version, tag, sizeof(tag), tag_data,
                                    MAX_METADATA_LENGTH_BYTES, &res);
  if (result != 0 || res.is_error) {
    printf("[%s:%d]: Can not send tagged data message!\n", __func__, __LINE__);
    free(tag_data);
    res_node_info_free(info);
    return -1;
  }
  free(tag_data);
  res_node_info_free(info);

  printf("[%s:%d]: Message successfully send! URL: http://%s:%d/api/v2/messages/0x%s\n", __func__, __LINE__, NODE_HOST,
         NODE_PORT, res.u.msg_id);

  // disable memory tracing
  muntrace();

  return 0;
}
