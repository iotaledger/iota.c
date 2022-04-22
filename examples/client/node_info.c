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
  if (info) {
    int ret = get_node_info(&ctx, info);
    if (ret == 0) {
      node_info_print(info, 0);
    } else {
      printf("Retrieving node info failed!\n");
    }
    res_node_info_free(info);
  } else {
    printf("Failed to create a response node info object!\n");
  }

  return 0;
}
