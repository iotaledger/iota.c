// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/payloads/payloads.h"
#include "client/api/restful/get_milestone.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

res_milestone_t *res_milestone_new() {
  res_milestone_t *ms = malloc(sizeof(res_milestone_t));
  if (ms) {
    ms->is_error = false;
    ms->u.ms = NULL;
    return ms;
  }
  return NULL;
}

void res_milestone_free(res_milestone_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.ms) {
        milestone_payload_free(res->u.ms);
      }
    }
    free(res);
  }
}

int deser_get_milestone(char const *const j_str, res_milestone_t *res) {
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

  // allocate milestone object
  res->u.ms = milestone_payload_new();
  if (!res->u.ms) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  // deserialize milestone object
  if ((ret = milestone_deserialize(json_obj, res->u.ms)) != 0) {
    printf("[%s:%d]: deserialize milestone error\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int get_milestone_by_id(iota_client_conf_t const *conf, char const ms_id[], res_milestone_t *res) {
  if (conf == NULL || ms_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(ms_id) != BIN_TO_HEX_BYTES(CRYPTO_BLAKE2B_256_HASH_BYTES)) {
    // invalid milestone id length
    printf("[%s:%d]: invalid milestone id length: %zu\n", __func__, __LINE__, strlen(ms_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str = "/api/v2/milestones/0x";

  cmd = iota_str_reserve(strlen(cmd_str) + BIN_TO_HEX_BYTES(CRYPTO_BLAKE2B_256_HASH_BYTES) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s", cmd_str, ms_id);
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
    ret = deser_get_milestone((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}
