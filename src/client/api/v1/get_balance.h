#ifndef __CLIENT_API_V1_BALANCE_H__
#define __CLIENT_API_V1_BALANCE_H__

#include <stdint.h>

#include "core/types.h"

// should we use balance_t? it supports colored coins but it seems Chrysalis still doesn't
//#include "core/balance.h"

typedef struct {
  byte_t addr[32];
  uint16_t maxResults;
  uint16_t count;
  uint64_t balance; //should we use balance_t?
} res_balance_t;

#endif  // __CLIENT_API_V1_BALANCE_H__
