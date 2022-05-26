// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifdef MTRACE_ENABLED
#include <mcheck.h>
#endif
#include <stdio.h>

#include "benchmark_config.h"
#include "client/api/restful/get_node_info.h"
#include "client/api/restful/send_tagged_data.h"
#include "client/constants.h"
#include "core/models/outputs/features.h"

int main() {
#ifdef MTRACE_ENABLED
  // enable memory tracing
  mtrace();
#endif

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
  res_send_block_t res = {};

  result = send_tagged_data_block(&ctx, info->u.output_node_info->protocol_version, tag, sizeof(tag), tag_data,
                                  MAX_METADATA_LENGTH_BYTES, &res);
  if (result != 0 || res.is_error) {
    printf("[%s:%d]: Can not send tagged data block!\n", __func__, __LINE__);
    free(tag_data);
    res_node_info_free(info);
    return -1;
  }
  free(tag_data);
  res_node_info_free(info);

  printf("[%s:%d]: Tagged Data successfully send! URL: http://%s:%d%s/blocks/0x%s\n", __func__, __LINE__, NODE_HOST,
         NODE_PORT, NODE_API_PATH, res.u.blk_id);

  return 0;
}
