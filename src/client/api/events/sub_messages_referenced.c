// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>

#include "client/api/events/sub_messages_referenced.h"
#include "client/api/json_utils.h"
#include "client/network/mqtt/mqtt.h"

int parse_messages_referenced(char *data, messages_referenced_t *res) {
  int ret = -1;
  cJSON *json_obj = cJSON_Parse((char *)data);
  if (json_obj == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return ret;
  }

  // message ID
  if ((ret = json_get_string(data_obj, JSON_KEY_MSG_ID, res->msg_id, sizeof(res->msg_id))) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
    goto end;
  }

  // parents
  if ((ret = json_string_array_to_utarray(data_obj, JSON_KEY_PARENT_IDS, res->parents)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
    goto end;
  }

  // solidation
  if ((ret = json_get_boolean(data_obj, JSON_KEY_IS_SOLID, &res->u.meta->is_solid)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_IS_SOLID);
    goto end;
  }

  // should promote
  if ((ret = json_get_boolean(data_obj, JSON_KEY_SHOULD_PROMOTE, &res->should_promote)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_SHOULD_PROMOTE);
    goto end;
  }

  // should reattach
  if ((ret = json_get_boolean(data_obj, JSON_KEY_SHOULD_REATTACH, &res->should_reattach)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_SHOULD_REATTACH);
    goto end;
  }

  // ledger inclusion state
  if ((ret = json_get_string(data_obj, JSON_KEY_LEDGER_ST, res->inclusion_state, sizeof(res->inclusion_state))) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_LEDGER_ST);
    goto end;
  }

  // gets referenced milestone index
  if ((ret = json_get_uint64(data_obj, JSON_KEY_REF_MILESTONE_IDX, res->referenced_milestone)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_REF_MILESTONE_IDX);
    goto end;
  }

end:

  cJSON_Delete(json_obj);
  return ret;
}