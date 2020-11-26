#include <stdio.h>
#include <string.h>

#include "client/api/json_utils.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"
#include "client/api/v1/get_balance.h"

int get_balance(iota_client_conf_t const *conf, byte_t addr[IOTA_ADDRESS_BYTES], res_balance_t *res) {
  int ret = 0;
  char const *const cmd_info = "api/v1/address";

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);
  if(addr == NULL || res == NULL ) {
    printf("[%s:%d]: get_balance failed (null parameter)\n", __func__, __LINE__);
    ret = -1;
  }

  if(sizeof(addr) != IOTA_ADDRESS_BYTES) {
    printf("[%s:%d]: get_balance failed (invalid address size)\n", __func__, __LINE__);
    ret = -1;
  }

  memcpy(res->addr, addr, strlen(addr)+1);

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
