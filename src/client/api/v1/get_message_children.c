// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_message_children.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

static msg_children_t *msg_children_new() {
  msg_children_t *ch = malloc(sizeof(msg_children_t));
  if (ch) {
    ch->max_results = 0;
    ch->count = 0;
    memset(ch->msg_id, 0, sizeof(ch->msg_id));
    utarray_new(ch->children, &ut_str_icd);
    return ch;
  }
  return NULL;
}

static void msg_children_free(msg_children_t *ch) {
  if (ch) {
    if (ch->children) {
      utarray_free(ch->children);
    }
    free(ch);
  }
}

res_msg_children_t *res_msg_children_new() {
  res_msg_children_t *res = malloc(sizeof(res_msg_children_t));
  if (res) {
    res->is_error = false;
    res->u.data = NULL;
    return res;
  }
  return NULL;
}

void res_msg_children_free(res_msg_children_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.data) {
        msg_children_free(res->u.data);
      }
    }
    free(res);
  }
}

size_t res_msg_children_len(res_msg_children_t *res) {
  if (res) {
    if (res->is_error == false) {
      if (res->u.data) {
        return utarray_len(res->u.data->children);
      }
    }
  }
  return 0;
}

char *res_msg_children_get(res_msg_children_t *res, size_t index) {
  if (res) {
    if (index < res_msg_children_len(res)) {
      char **p = (char **)utarray_eltptr(res->u.data->children, index);
      return *p;
    }
  }
  return NULL;
}

int deser_msg_children(char const *const j_str, res_msg_children_t *res) {
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
    res->u.data = msg_children_new();
    if (res->u.data == NULL) {
      printf("[%s:%d]: msg_children_t object allocation filaed\n", __func__, __LINE__);
      goto end;
    }

    // message ID
    if ((ret = json_get_string(data_obj, JSON_KEY_MSG_ID, res->u.data->msg_id, sizeof(res->u.data->msg_id))) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
      goto end;
    }

    // max results
    if ((ret = json_get_uint32(data_obj, JSON_KEY_MAX_RESULTS, &res->u.data->max_results)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MAX_RESULTS);
      goto end;
    }

    // count
    if ((ret = json_get_uint32(data_obj, JSON_KEY_COUNT, &res->u.data->count)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_COUNT);
      goto end;
    }

    // children
    if ((ret = json_string_array_to_utarray(data_obj, JSON_KEY_CHILDREN_MSG_IDS, res->u.data->children)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_CHILDREN_MSG_IDS);
    }

  } else {
    printf("[%s:%d]: JSON parsing failed\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int get_message_children(iota_client_conf_t const *ctx, char const msg_id[], res_msg_children_t *res) {
  int ret = -1;
  iota_str_t *cmd = NULL;
  byte_buf_t *http_res = NULL;
  long st = 0;
  char const *const cmd_prefix = "/api/v1/messages/";
  char const *const cmd_suffix = "/children";

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
    ret = deser_msg_children((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}
