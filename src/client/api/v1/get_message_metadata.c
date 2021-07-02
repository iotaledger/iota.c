// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_message_metadata.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

static msg_meta_t *msg_meta_new() {
  msg_meta_t *meta = malloc(sizeof(msg_meta_t));
  if (meta) {
    utarray_new(meta->parents, &ut_str_icd);
    meta->is_solid = false;
    meta->should_promote = -1;
    meta->should_reattach = -1;
    meta->referenced_milestone = 0;
    meta->milestone_idx = 0;
    return meta;
  }
  return NULL;
}

static void msg_meta_free(msg_meta_t *meta) {
  if (meta) {
    if (meta->parents) {
      utarray_free(meta->parents);
    }
    free(meta);
  }
}

res_msg_meta_t *res_msg_meta_new() {
  res_msg_meta_t *res = malloc(sizeof(res_msg_meta_t));
  if (res) {
    res->is_error = false;
    res->u.meta = NULL;
    return res;
  }
  return NULL;
}

void res_msg_meta_free(res_msg_meta_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.meta) {
        msg_meta_free(res->u.meta);
      }
    }
    free(res);
  }
}

size_t res_msg_meta_parents_len(res_msg_meta_t *res) {
  if (res) {
    if (res->is_error == false) {
      if (res->u.meta) {
        return utarray_len(res->u.meta->parents);
      }
    }
  }
  return 0;
}

char *res_msg_meta_parent_get(res_msg_meta_t *res, size_t index) {
  if (res) {
    if (index < res_msg_meta_parents_len(res)) {
      char **p = (char **)utarray_eltptr(res->u.meta->parents, index);
      return *p;
    }
  }
  return NULL;
}

int deser_msg_meta(char const *const j_str, res_msg_meta_t *res) {
  int ret = -1;
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    ret = 0;
    goto end;
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_DATA);
  if (data_obj) {
    // allocate message metadata object after parsing json object.
    res->u.meta = msg_meta_new();
    if (res->u.meta == NULL) {
      printf("[%s:%d]: msg_meta_t object allocation filaed\n", __func__, __LINE__);
      goto end;
    }

    // message ID
    if ((ret = json_get_string(data_obj, JSON_KEY_MSG_ID, res->u.meta->msg_id, sizeof(res->u.meta->msg_id))) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
      goto end;
    }

    // parents
    if ((ret = json_string_array_to_utarray(data_obj, JSON_KEY_PARENT_IDS, res->u.meta->parents)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
      goto end;
    }

    // solidation
    if ((ret = json_get_boolean(data_obj, JSON_KEY_IS_SOLID, &res->u.meta->is_solid)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_IS_SOLID);
      goto end;
    }

    bool temp_bool = false;
    // should promote
    if (json_get_boolean(data_obj, JSON_KEY_SHOULD_PROMOTE, &temp_bool) == 0) {
      // the key is presented
      res->u.meta->should_promote = temp_bool ? 1 : 0;
    }

    // should reattach
    if (json_get_boolean(data_obj, JSON_KEY_SHOULD_REATTACH, &temp_bool) == 0) {
      // the key is presented
      res->u.meta->should_reattach = temp_bool ? 1 : 0;
    }

    // ledger inclusion state
    json_get_string(data_obj, JSON_KEY_LEDGER_ST, res->u.meta->inclusion_state, sizeof(res->u.meta->inclusion_state));

    // gets referenced milestone index
    json_get_uint64(data_obj, JSON_KEY_REF_MILESTONE_IDX, &res->u.meta->referenced_milestone);

    // gets milestone index
    json_get_uint64(data_obj, JSON_KEY_MILESTONE_IDX, &res->u.meta->milestone_idx);

  } else {
    printf("[%s:%d]: JSON parsing failed\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int get_message_metadata(iota_client_conf_t const *ctx, char const msg_id[], res_msg_meta_t *res) {
  int ret = -1;
  iota_str_t *cmd = NULL;
  byte_buf_t *http_res = NULL;
  long st = 0;
  char const *const cmd_prefix = "/api/v1/messages/";
  char const *const cmd_suffix = "/metadata";

  if (ctx == NULL || msg_id == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }
  size_t msg_str_len = strlen(msg_id);
  if (msg_str_len != IOTA_MESSAGE_ID_HEX_BYTES) {
    printf("[%s:%d] incorrect length of the message ID\n", __func__, __LINE__);
    return -1;
  }

  cmd = iota_str_reserve(strlen(cmd_prefix) + msg_str_len + strlen(cmd_suffix) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s", cmd_prefix, msg_id, cmd_suffix);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = ctx->host, .path = cmd->buf, .use_tls = ctx->use_tls, .port = ctx->port};

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_msg_meta((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}