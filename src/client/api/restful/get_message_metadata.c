// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_message_metadata.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

msg_meta_t *metadata_new() {
  msg_meta_t *meta = malloc(sizeof(msg_meta_t));
  if (meta) {
    utarray_new(meta->parents, &ut_str_icd);
    meta->is_solid = false;
    meta->should_promote = -1;
    meta->should_reattach = -1;
    meta->referenced_milestone = 0;
    meta->milestone_idx = 0;
    memset(meta->inclusion_state, 0, sizeof(meta->inclusion_state));
    meta->conflict_reason = 0;
    return meta;
  }
  return NULL;
}

void metadata_free(msg_meta_t *meta) {
  if (meta) {
    if (meta->parents) {
      utarray_free(meta->parents);
    }
    free(meta);
  }
}

res_msg_meta_t *msg_meta_new() {
  res_msg_meta_t *res = malloc(sizeof(res_msg_meta_t));
  if (res) {
    res->is_error = false;
    res->u.meta = NULL;
    return res;
  }
  return NULL;
}

void msg_meta_free(res_msg_meta_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.meta) {
        metadata_free(res->u.meta);
      }
    }
    free(res);
  }
}

size_t msg_meta_parents_count(msg_meta_t *msg) {
  if (msg) {
    return utarray_len(msg->parents);
  }
  return 0;
}

char *msg_meta_parent_get(msg_meta_t *msg, size_t index) {
  if (msg) {
    if (index < msg_meta_parents_count(msg)) {
      char **p = (char **)utarray_eltptr(msg->parents, index);
      return *p;
    }
  }
  return NULL;
}

int parse_messages_metadata(char const *const j_str, msg_meta_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  cJSON *json_obj = cJSON_Parse(j_str);
  if (!json_obj) {
    printf("[%s:%d]: can not parse JSON object\n", __func__, __LINE__);
    return -1;
  }

  // message ID
  if ((ret = json_get_string_with_prefix(json_obj, JSON_KEY_MSG_ID, res->msg_id, sizeof(res->msg_id))) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
    goto end;
  }

  // parents
  if ((ret = json_string_with_prefix_array_to_utarray(json_obj, JSON_KEY_PARENT_IDS, res->parents)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
    goto end;
  }

  // solidation
  if ((ret = json_get_boolean(json_obj, JSON_KEY_IS_SOLID, &res->is_solid)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_IS_SOLID);
    goto end;
  }

  bool temp_bool = false;
  // should promote
  if (json_get_boolean(json_obj, JSON_KEY_SHOULD_PROMOTE, &temp_bool) == 0) {
    // the key is presented
    res->should_promote = temp_bool ? 1 : 0;
  }

  // should reattach
  if (json_get_boolean(json_obj, JSON_KEY_SHOULD_REATTACH, &temp_bool) == 0) {
    // the key is presented
    res->should_reattach = temp_bool ? 1 : 0;
  }

  // ledger inclusion state
  json_get_string(json_obj, JSON_KEY_LEDGER_ST, res->inclusion_state, sizeof(res->inclusion_state));

  // has conflict reason
  json_get_uint8(json_obj, JSON_KEY_CONFLICT_REASON, &res->conflict_reason);

  // gets referenced milestone index
  json_get_uint32(json_obj, JSON_KEY_REF_MILESTONE_IDX, &res->referenced_milestone);

  // gets milestone index
  json_get_uint32(json_obj, JSON_KEY_MILESTONE_IDX, &res->milestone_idx);

end:
  cJSON_Delete(json_obj);
  return ret;
}

int msg_meta_deserialize(char const *const j_str, res_msg_meta_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (!json_obj) {
    printf("[%s:%d]: can not parse JSON object\n", __func__, __LINE__);
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    cJSON_Delete(json_obj);
    return 0;
  }
  cJSON_Delete(json_obj);

  // allocate message metadata object after parsing json object.
  res->u.meta = metadata_new();
  if (!res->u.meta) {
    printf("[%s:%d]: msg_meta_t object allocation failed\n", __func__, __LINE__);
    return -1;
  }

  return parse_messages_metadata(j_str, res->u.meta);
}

int get_message_metadata(iota_client_conf_t const *ctx, char const msg_id[], res_msg_meta_t *res) {
  if (ctx == NULL || msg_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  size_t msg_str_len = strlen(msg_id);
  if (msg_str_len != BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES)) {
    printf("[%s:%d] incorrect length of the message ID\n", __func__, __LINE__);
    return -1;
  }

  char const *const cmd_prefix = "/messages/0x";
  char const *const cmd_suffix = "/metadata";

  iota_str_t *cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_prefix) + msg_str_len + strlen(cmd_suffix) + 1);
  if (!cmd) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s%s", NODE_API_PATH, cmd_prefix, msg_id, cmd_suffix);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = ctx->host, .path = cmd->buf, .use_tls = ctx->use_tls, .port = ctx->port};

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long st = 0;
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = msg_meta_deserialize((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

void print_message_metadata(res_msg_meta_t *res, uint8_t indentation) {
  if (res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }
  if (res->is_error) {
    printf("Error: %s\n", res->u.error->msg);
  } else {
    msg_meta_t *meta = res->u.meta;
    printf("%s{\n", PRINT_INDENTATION(indentation));
    printf("%s\tmessageId: %s\n", PRINT_INDENTATION(indentation), meta->msg_id);
    int len = utarray_len(meta->parents);
    if (len > 0) {
      printf("%s\tparentMessageIds: [\n", PRINT_INDENTATION(indentation));
      for (int i = 0; i < len; i++) {
        printf(i > 0 ? ",\n" : "");
        printf("%s\t\t%s", PRINT_INDENTATION(indentation), *(char **)utarray_eltptr(meta->parents, (unsigned int)i));
      }
      printf("\n");
      printf("%s\t]\n", PRINT_INDENTATION(indentation));
    } else {
      printf("%s\tparentMessageIds: []\n", PRINT_INDENTATION(indentation));
    }
    printf("%s\tisSolid: %s\n", PRINT_INDENTATION(indentation), meta->is_solid ? "true" : "false");
    printf("%s\treferencedByMilestoneIndex: %u\n", PRINT_INDENTATION(indentation), meta->referenced_milestone);
    printf("%s\tmilestoneIndex: %u\n", PRINT_INDENTATION(indentation), meta->milestone_idx);
    if (!buf_all_zeros((uint8_t *)meta->inclusion_state, sizeof(meta->inclusion_state))) {
      printf("%s\tledgerInclustionState: %s\n", PRINT_INDENTATION(indentation), meta->inclusion_state);
    }
    if (meta->conflict_reason > 0) {
      printf("%s\tconflictReason: %d\n", PRINT_INDENTATION(indentation), meta->conflict_reason);
    }
    if (meta->should_promote >= 0) {
      printf("%s\tshouldPromote: %s\n", PRINT_INDENTATION(indentation), meta->should_promote ? "true" : "false");
    }
    if (meta->should_reattach >= 0) {
      printf("%s\tshouldReattach: %s\n", PRINT_INDENTATION(indentation), meta->should_reattach ? "true" : "false");
    }
    printf("%s}\n", PRINT_INDENTATION(indentation));
  }
}
