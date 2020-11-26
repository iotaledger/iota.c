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
  int ret = 0;

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    // gets addr
    if ((ret = json_get_string(data_obj, key_addr, res->addr, sizeof(res->addr))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_addr);
      ret = -1;
      goto end;
    }

    // gets maxResults
    if ((ret = json_get_string(data_obj, key_maxResults, res->maxResults, sizeof(res->maxResults))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_maxResults);
      ret = -1;
      goto end;
    }

    // gets count
    if ((ret = json_get_boolean(data_obj, key_count, &res->count)) != 0) {
      printf("[%s:%d]: gets %s json boolean failed\n", __func__, __LINE__, key_count);
      ret = -1;
      goto end;
    }

    // gets balance
    if ((ret = json_get_boolean(data_obj, key_balance, &res->balance)) != 0) {
      printf("[%s:%d]: gets %s json boolean failed\n", __func__, __LINE__, key_balance);
      ret = -1;
      goto end;
    }

  end:
    cJSON_Delete(json_obj);
    return ret;
  }
}

int get_balance(iota_client_conf_t const *conf, byte_t addr[IOTA_ADDRESS_BYTES], res_balance_t *res) {
  int ret = 0;
  char const *const cmd_info = "api/v1/address";

  if (addr == NULL || res == NULL || conf == NULL) {
    printf("[%s:%d]: get_balance failed (null parameter)\n", __func__, __LINE__);
    return -1;
  }

  memcpy(res->addr, addr, strlen(addr) + 1);

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);

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
  http_client_get(&http_conf, http_res);
  byte_buf2str(http_res);

  // json deserialization
  // deser_node_info((char const *const)http_res->data, res);

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);

  return ret;

  // ...

  return ret;
}
