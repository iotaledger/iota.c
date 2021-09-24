// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>

#include "client/api/v1/get_node_info.h"

int main(void) {
  iota_client_conf_t ctx = {.host = "chrysalis-nodes.iota.org", .port = 443, .use_tls = true};
  res_node_info_t *info = res_node_info_new();
  if (info) {
    int ret = get_node_info(&ctx, info);
    if (ret == 0) {
      if (!info->is_error) {
        printf("Name: %s\n", info->u.output_node_info->name);
        printf("Version: %s\n", info->u.output_node_info->version);
        printf("isHealthy: %s\n", info->u.output_node_info->is_healthy ? "true" : "false");
        printf("Network ID: %s\n", info->u.output_node_info->network_id);
        printf("bech32HRP: %s\n", info->u.output_node_info->bech32hrp);
        printf("minPoWScore: %" PRIu64 "\n", info->u.output_node_info->min_pow_score);
        printf("Latest Milestone Index: %" PRIu64 "\n", info->u.output_node_info->latest_milestone_index);
        printf("Latest Milestone Timestamp: %" PRIu64 "\n", info->u.output_node_info->latest_milestone_timestamp);
        printf("Confirmed Milestone Index: %" PRIu64 "\n", info->u.output_node_info->confirmed_milestone_index);
        printf("Pruning Index: %" PRIu64 "\n", info->u.output_node_info->pruning_milestone_index);
        printf("MSP: %0.2f\n", info->u.output_node_info->msg_pre_sec);
        printf("Referenced MPS: %0.2f\n", info->u.output_node_info->referenced_msg_pre_sec);
        printf("Reference Rate: %0.2f%%\n", info->u.output_node_info->referenced_rate);
      } else {
        printf("Node response: %s\n", info->u.error->msg);
      }
    } else {
      printf("get node info API failed\n");
    }
    res_node_info_free(info);
  } else {
    printf("new respose object failed\n");
  }

  return 0;
}