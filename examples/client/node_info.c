// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of getting a node info.
 *
 */

#include <stdio.h>

#include "client/api/restful/get_node_info.h"

int main(void) {
  iota_client_conf_t ctx = {.host = "localhost", .port = 443, .use_tls = true};

  res_node_info_t *info = res_node_info_new();

  if (!info) {
    printf("Failed to create a response node info object!\n");
    return -1;
  }

  if (get_node_info(&ctx, info) != 0) {
    printf("Retrieving node info failed!\n");
    res_node_info_free(info);
    return -1;
  }

  if (info->is_error) {
    // got an error message from node.
    printf("Error: %s\n", info->u.error->msg);
  } else {
    node_info_print(info, 0);
  }

  res_node_info_free(info);

  return 0;
}
