// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_tips.h"
#include "core/utils/iota_str.h"

int get_tips(iota_client_conf_t const *conf, res_tips_t *res) {
  int ret = -1;
  long st = 0;
  byte_buf_t *http_res = NULL;
  char const *const cmd_tips = "api/v1/tips";

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);
  if (cmd == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, cmd_tips)) {
    printf("[%s:%d]: string append failed\n", __func__, __LINE__);
    goto done;
  }

  // http client configuration
  http_client_config_t http_conf = {0};
  http_conf.url = cmd->buf;
  if (conf->port) {
    http_conf.port = conf->port;
  }

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_tips((char const *const)http_res->data, res);
  } else {
    printf("[%s:%d] network error\n", __func__, __LINE__);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);

  return ret;
}

res_tips_t *res_tips_new() {
  res_tips_t *tips = malloc(sizeof(res_tips_t));
  if (tips) {
    tips->is_error = false;
    return tips;
  }
  return NULL;
}

void res_tips_free(res_tips_t *tips) {
  if (tips) {
    if (tips->is_error) {
      res_err_free(tips->u.error);
    }
    free(tips);
  }
}

int deser_get_tips(char const *const j_str, res_tips_t *res) {
  int ret = -1;

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
    // gets tip1
    if ((ret = json_get_string(data_obj, JSON_KEY_TIP1_ID, res->u.tips.tip1, STR_TIP_MSG_LEN)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_TIP1_ID);
      goto end;
    }

    // gets tip2
    if ((ret = json_get_string(data_obj, JSON_KEY_TIP2_ID, res->u.tips.tip2, STR_TIP_MSG_LEN)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_TIP2_ID);
    }
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}
