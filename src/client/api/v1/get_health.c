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
  byte_buf_t *http_res = NULL;

  // http client configuration
  http_client_config_t http_conf = {
      .host = conf->host, .path = "/health", .use_tls = conf->use_tls, .port = conf->port};

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
  byte_buf_free(http_res);

  return ret;
}
