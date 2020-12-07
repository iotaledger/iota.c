// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_balance.h"
#include "client/api/v1/response_error.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

int deser_balance_info(char const *const j_str, res_balance_t *res) {
  char const *const key_addr = "address";
  char const *const key_maxResults = "maxResults";
  char const *const key_count = "count";
  char const *const key_balance = "balance";
  char const *const key_code = "code";
  char const *const key_message = "message";
  double *number;
  int ret = 0;

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  cJSON *error_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_error);
  if (error_obj) {
    char *code = calloc(32, sizeof(char));

    // gets err code
    if ((ret = json_get_string(error_obj, key_code, code, 32)) != 0) {
      printf("[%s:%d]: gets %s json error code failed\n", __func__, __LINE__, key_addr);
      ret = -1;
      free(code);
      goto end;
    }

    if (strcmp(code, "invalid_data") == 0) {
      printf("[%s:%d]: http code 400\n", __func__, __LINE__, key_addr);
      ret = -1;
      free(code);
      goto end;

    } else if (strcmp(code, "not_found") == 0) {
      printf("[%s:%d]: http code 404\n", __func__, __LINE__, key_addr);
      ret = -1;
      free(code);
      goto end;
    }

    free(code);
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    // gets addr
    char *addr = calloc(64, sizeof(char));
    if ((ret = json_get_string(data_obj, key_addr, addr, 64)) != 0) {
      printf("[%s:%d]: gets %s json addr failed\n", __func__, __LINE__, key_addr);
      ret = -1;
      goto end;
    }

    if (strlen(addr) == 64) {
      byte_t addr_bytes[IOTA_ADDRESS_BYTES];
      hex2bin(addr, addr_bytes + 1, IOTA_ADDRESS_BYTES - 1);
      addr_bytes[0] = 0x0001;  // Ed25519
      memcpy(res->addr, addr_bytes, IOTA_ADDRESS_BYTES);
    } else {
      printf("[%s:%d]: gets %s json addr failed\n", __func__, __LINE__, key_addr);
      ret = -1;
      goto end;
    }

    free(addr);

    // gets maxResults
    if ((ret = json_get_uint16(data_obj, key_maxResults, res->maxResults)) != 0) {
      printf("[%s:%d]: gets %s json maxResults failed\n", __func__, __LINE__, key_maxResults);
      ret = -1;
      goto end;
    }

    res->maxResults = (uint16_t)*number;

    // gets count
    if ((ret = json_get_uint16(data_obj, key_count, res->count)) != 0) {
      printf("[%s:%d]: gets %s json count failed\n", __func__, __LINE__, key_count);
      ret = -1;
      goto end;
    }

    res->count = (uint16_t)*number;

    // gets balance
    if ((ret = json_get_uint64(data_obj, key_balance, res->balance)) != 0) {
      printf("[%s:%d]: gets %s json balance failed\n", __func__, __LINE__, key_balance);
      ret = -1;
      goto end;
    }

    res->balance = (int64_t)*number;

  end:
    cJSON_Delete(json_obj);
    return ret;
  }
}

int get_balance(iota_client_conf_t const *conf, char *addr, res_balance_t *res) {
  int ret = 0;
  char const *const cmd_info = "api/v1/address/";

  if (addr == NULL || res == NULL || conf == NULL) {
    printf("[%s:%d]: get_balance failed (null parameter)\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(addr) != 64 && strlen(addr) != 81) {
    printf("[%s:%d]: get_balance failed (invalid addr length)\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);

  if (iota_str_append(cmd, cmd_info)) {
    printf("[%s:%d]: cmd_info append failed\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, addr)) {
    printf("[%s:%d]: addr append failed\n", __func__, __LINE__);
    return -1;
  }

  // http client configuration
  http_client_config_t http_conf = {0};
  http_conf.url = cmd->buf;
  if (conf->port) {
    http_conf.port = conf->port;
  }

  byte_buf_t *http_res = byte_buf_new();
  if (http_res == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    // TODO
    ret = -1;
    goto done;
  }

  // send request via http client
  int http_err = http_client_get(&http_conf, http_res);
  if (http_err != 0) {
    ret = -1;
    goto done;
  }

  byte_buf2str(http_res);

  // json deserialization
  deser_balance_info((char const *const)http_res->data, res);

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);

  return ret;
}
