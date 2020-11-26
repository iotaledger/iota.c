#include <stdio.h>
#include <string.h>

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

  // ...

  return ret;
}
