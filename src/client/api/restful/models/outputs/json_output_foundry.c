// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/models/outputs/json_output_foundry.h"

int json_output_foundry_deserialize(cJSON *output_obj, transaction_essence_t *essence) {
  if (output_obj == NULL || essence == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}
