// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_balance.h"
#include "client/api/v1/response_error.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

res_balance_t *res_balance_new() {
  res_balance_t *res = malloc(sizeof(res_balance_t));
  if (res) {
    res->is_error = false;
    res->u.output_balance = NULL;
    return res;
  }
  return NULL;
}

void res_balance_free(res_balance_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.output_balance) {
        free(res->u.output_balance);
      }
    }
    free(res);
  }
}

int deser_balance_info(char const *const j_str, res_balance_t *res) {
  int ret = -1;

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
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

  res->u.output_balance = malloc(sizeof(get_balance_t));
  if (res->u.output_balance == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    goto end;
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_DATA);
  if (data_obj) {
    // gets address type
    if ((ret = json_get_uint8(data_obj, JSON_KEY_ADDR_TYPE, &res->u.output_balance->address_type)) != 0) {
      printf("[%s:%d]: gets %s json max_results failed\n", __func__, __LINE__, JSON_KEY_ADDR_TYPE);
      goto end;
    }

    // gets address
    if ((ret = json_get_string(data_obj, JSON_KEY_ADDR, res->u.output_balance->address,
                               sizeof(res->u.output_balance->address))) != 0) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_ADDR);
      goto end;
    }

    // gets balance
    if ((ret = json_get_uint64(data_obj, JSON_KEY_BALANCE, &res->u.output_balance->balance)) != 0) {
      printf("[%s:%d]: gets %s json balance failed\n", __func__, __LINE__, JSON_KEY_BALANCE);
      goto end;
    }
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int get_balance(iota_client_conf_t const *conf, char const addr[], res_balance_t *res) {
  int ret = -1;
  char const *const cmd_balance = "/api/v1/addresses/ed25519/";
  byte_buf_t *http_res = NULL;
  long http_st = 0;

  if (addr == NULL || res == NULL || conf == NULL) {
    printf("[%s:%d]: get_balance failed (null parameter)\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(addr) != IOTA_ADDRESS_HEX_BYTES) {
    printf("[%s:%d]: get_balance failed (invalid addr length)\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  iota_str_t *cmd = iota_str_new(cmd_balance);
  if (cmd == NULL) {
    printf("[%s:%d]: cmd_balance append failed\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, addr)) {
    printf("[%s:%d]: addr append failed\n", __func__, __LINE__);
    goto done;
  }

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  if ((ret = http_client_get(&http_conf, http_res, &http_st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_balance_info((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);

  return ret;
}
