
// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/mqtt/sub_milestone_latest.h"
#include <stdlib.h>
#include "client/api/json_utils.h"
#include "client/network/mqtt/mqtt.h"

void (*milestone_latest_cb)(res_milestone_latest_t *res);

res_milestone_latest_t *res_milestone_latest_new(void){
  res_milestone_latest_t *res = (res_milestone_latest_t *)malloc(sizeof(res_milestone_latest_t));
  if (res) {
    res->is_error = false;
    res->u.received_milestone_latest = (milestone_latest_t *)malloc(sizeof(milestone_latest_t));
    return res;
  }
  return NULL;
}

void res_milestone_latest_free(res_milestone_latest_t *res) {
  if (res) {
    if (res->is_error) {
      free(res->u.error);
    } else {
      if (res->u.received_milestone_latest) {
        free(res->u.received_milestone_latest);
      }
    }
    free(res);
  }
}

void mqtt_cb_milestone_latest(void *payload) {

  cJSON *json_obj = cJSON_Parse((char *)payload);
  if (json_obj == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    goto end;
  }

  // Allocates milestone latest response object
  res_milestone_latest_t *res = res_milestone_latest_new();

  // Parse index
  if ((json_get_uint32(json_obj, JSON_KEY_INDEX, &(res->u.received_milestone_latest->index))) != 0) {
    printf("[%s:%d]: parse %s failed\n", __func__, __LINE__, JSON_KEY_INDEX);
    res->is_error = true;
    char *error_msg = "Parse index failed";
    res->u.error = (char*)malloc(strlen(error_msg));
    strcpy(res->u.error, error_msg);
    goto end;
  }

  // Parse timestamp
  if ((json_get_uint64(json_obj, JSON_KEY_TIMESTAMP, &(res->u.received_milestone_latest->timestamp))) != 0) {
    printf("[%s:%d]: parse %s failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    res->is_error = true;
    char *error_msg = "Parse timestamp failed";
    res->u.error = (char*)malloc(strlen(error_msg));
    strcpy(res->u.error, error_msg);
    goto end;
  }

end:
  // Pass response to user defined callback function
  (*milestone_latest_cb)(res);
  // Delete json object created
  cJSON_Delete(json_obj);
  // Free response object
  res_milestone_latest_free(res);
}

int sub_milestone_latest(void (*callback)(res_milestone_latest_t *)) {
  mqtt_subscribe("milestones/latest", mqtt_cb_milestone_latest, 1);
  milestone_latest_cb = callback;
  return 0;
}