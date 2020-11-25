#include <stdio.h>
#include <string.h>

#include "client/api/v1/get_balance.h"

int get_balance(byte_t addr[IOTA_ADDRESS_BYTES], res_balance_t *res) {

  if(addr == NULL || res == NULL ) {
    printf("[%s:%d]: get_balance failed (null parameter)\n", __func__, __LINE__);
    return -1;
  }

  if(sizeof(addr) != IOTA_ADDRESS_BYTES) {
    printf("[%s:%d]: get_balance failed (invalid address size)\n", __func__, __LINE__);
    return -1;
  }

  memcpy(res->addr, addr, strlen(addr)+1);

  // ...

  return 0;
}
