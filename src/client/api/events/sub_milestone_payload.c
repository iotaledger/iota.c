// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>

#include "client/api/events/sub_milestone_payload.h"
#include "client/api/json_parser/json_utils.h"
#include "client/network/mqtt/mqtt.h"

int parse_milestone_payload(char *data, milestone_payload_t *res) {
  if (res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse((char *)data);
  if (json_obj == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  // Parse index
  if (json_get_uint32(json_obj, JSON_KEY_INDEX, &(res->index)) != 0) {
    printf("[%s:%d]: parse %s failed\n", __func__, __LINE__, JSON_KEY_INDEX);
    return -1;
  }

  // Parse timestamp
  if (json_get_uint32(json_obj, JSON_KEY_TIMESTAMP, &(res->timestamp)) != 0) {
    printf("[%s:%d]: parse %s failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    return -1;
  }

  cJSON_Delete(json_obj);
  return 0;
}