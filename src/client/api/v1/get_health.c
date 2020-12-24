// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "client/api/v1/get_health.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

int get_health(iota_client_conf_t const *conf, bool *health) {
  int ret = -1;
  long st = 0;
  char const *const cmd_info = "health";
  byte_buf_t *http_res = NULL;

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);
  if (cmd == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, cmd_info)) {
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

  ret = http_client_get(&http_conf, http_res, &st);
  if (st == 200 && ret == 0) {
    *health = true;
  } else {
    *health = false;
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);

  return ret;
}
