
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/mqtt/sub_milestone_latest.h"
#include <stdlib.h>
#include "client/api/json_utils.h"
#include "client/network/mqtt/mqtt.h"

void (*milestone_latest_cb)(res_milestone_latest_t *res);

void mqtt_cb_milestone_latest(void *payload) {
  res_milestone_latest_t *response = (res_milestone_latest_t *)malloc(sizeof(res_milestone_latest_t));

  // To Do : Handle Error Case

  response->is_error = false;
  response->u.received_milestone_latest = (milestone_latest_t *)malloc(sizeof(milestone_latest_t));

  cJSON *json_obj = cJSON_Parse((char *)payload);
  if (json_obj == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
  }

  // gets index
  if ((json_get_uint32(json_obj, JSON_KEY_INDEX, &(response->u.received_milestone_latest->index))) != 0) {
    printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_INDEX);
    goto end;
  }

  // gets timestamp
  if ((json_get_uint64(json_obj, JSON_KEY_TIMESTAMP, &(response->u.received_milestone_latest->timestamp))) != 0) {
    printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    goto end;
  }
  // Pass response to user defined callback function
  (*milestone_latest_cb)(response);

end:
  cJSON_Delete(json_obj);
}

int sub_milestone_latest(void (*callback)(res_milestone_latest_t *)) {
  mqtt_subscribe("milestones/latest", mqtt_cb_milestone_latest, 1);
  milestone_latest_cb = callback;
  return 0;
}