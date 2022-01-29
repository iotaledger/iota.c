// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/feat_blocks.h"

int json_feat_blocks_deserialize(cJSON *output_obj, feat_blk_list_t *feat_blocks) {
  if (output_obj == NULL || feat_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}
