// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_parser/message.h"
#include "client/api/restful/get_message.h"
#include "client/network/http.h"
#include "core/address.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

res_message_t *res_message_new() {
  res_message_t *msg = malloc(sizeof(res_message_t));
  if (msg) {
    msg->is_error = false;
    msg->u.msg = NULL;
    return msg;
  }
  return NULL;
}

void res_message_free(res_message_t *msg) {
  if (msg) {
    if (msg->is_error) {
      res_err_free(msg->u.error);
    } else {
      if (msg->u.msg) {
        core_message_free(msg->u.msg);
      }
    }
    free(msg);
  }
}

int deser_get_message(char const *const j_str, res_message_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    printf("[%s:%d]: parsing JSON message failed\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;
  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    ret = 0;
    goto end;
  }

  // allocate message object
  res->u.msg = core_message_new(0);
  if (!res->u.msg) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  // deserialize message object
  if ((ret = json_message_deserialize(json_obj, res->u.msg)) != 0) {
    printf("[%s:%d]: deserialize message error\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);

  return ret;
}

int get_message_by_id(iota_client_conf_t const *conf, char const msg_id[], res_message_t *res) {
  if (conf == NULL || msg_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(msg_id) != BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES)) {
    // invalid message id length
    printf("[%s:%d]: invalid message id length: %zu\n", __func__, __LINE__, strlen(msg_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str = "/api/v2/messages/0x";

  cmd = iota_str_reserve(strlen(cmd_str) + BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s", cmd_str, msg_id);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  int ret = -1;

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long st = 0;
  ret = http_client_get(&http_conf, http_res, &st);
  if (ret == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_message((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}
