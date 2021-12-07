// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>

#include "client/api/events/sub_messages_metadata.h"
#include "client/api/json_utils.h"
#include "client/network/mqtt/mqtt.h"

msg_metadata_t *res_msg_metadata_new(void) {
  msg_metadata_t *res = malloc(sizeof(msg_metadata_t));
  if (res) {
    utarray_new(res->parents, &ut_str_icd);
    res->is_solid = false;
    res->should_promote = false;
    res->should_reattach = false;
    res->referenced_milestone = 0;
    return res;
  }
  return NULL;
}

void res_msg_metadata_free(msg_metadata_t *res) {
  if (res) {
    if (res->parents) {
      utarray_free(res->parents);
    }
    free(res);
  }
}

size_t res_msg_metadata_parents_len(msg_metadata_t *res) {
  if (res) {
    return utarray_len(res->parents);
  }
  return 0;
}

char *res_msg_metadata_parent_get(msg_metadata_t *res, size_t index) {
  if (res) {
    if (index < res_msg_metadata_parents_len(res)) {
      char **p = (char **)utarray_eltptr(res->parents, index);
      return *p;
    }
  }
  return NULL;
}

int parse_messages_metadata(char *data, msg_metadata_t *res) {
  int ret = -1;
  cJSON *json_obj = cJSON_Parse((char *)data);
  if (json_obj == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return ret;
  }

  // message ID
  if ((ret = json_get_string(json_obj, JSON_KEY_MSG_ID, res->msg_id, sizeof(res->msg_id))) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
    goto end;
  }

  // parents
  if ((ret = json_string_array_to_utarray(json_obj, JSON_KEY_PARENT_IDS, res->parents)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
    goto end;
  }

  // ledger inclusion state
  if ((ret = json_get_string(json_obj, JSON_KEY_LEDGER_ST, res->inclusion_state, sizeof(res->inclusion_state))) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_LEDGER_ST);
    goto end;
  }

  // solidation
  if ((ret = json_get_boolean(json_obj, JSON_KEY_IS_SOLID, &res->is_solid)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_IS_SOLID);
    goto end;
  }

  // should promote
  if (cJSON_HasObjectItem(json_obj, JSON_KEY_SHOULD_PROMOTE)) {
    if ((ret = json_get_boolean(json_obj, JSON_KEY_SHOULD_PROMOTE, &res->should_promote)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_SHOULD_PROMOTE);
      goto end;
    }
  }

  // should reattach
  if (cJSON_HasObjectItem(json_obj, JSON_KEY_SHOULD_REATTACH)) {
    if ((ret = json_get_boolean(json_obj, JSON_KEY_SHOULD_REATTACH, &res->should_reattach)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_SHOULD_REATTACH);
      goto end;
    }
  }

  // gets metadata milestone index
  if (cJSON_HasObjectItem(json_obj, JSON_KEY_REF_MILESTONE_IDX)) {
    if ((ret = json_get_uint64(json_obj, JSON_KEY_REF_MILESTONE_IDX, &res->referenced_milestone)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_REF_MILESTONE_IDX);
      goto end;
    }
  }

end:

  cJSON_Delete(json_obj);
  return ret;
}

int event_subscribe_msg_metadata(event_client_handle_t client, int *mid, char const msg_id[], int qos) {
  if ((strlen(msg_id)) != MSG_ID_LEN) {
    printf("[%s:%d]: Message Id length is invalid\n", __func__, __LINE__);
    return 0;
  }
  // Buffer to store topic string : messages/{messageid}/metadata
  char topic_buff[MSG_ID_LEN + 19] = {0};
  // Prepare topic string
  sprintf(topic_buff, "messages/%s/metadata", msg_id);
  // Call to MQTT network layer
  return event_subscribe(client, mid, topic_buff, qos);
}