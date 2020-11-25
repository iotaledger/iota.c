#ifndef __CLIENT_API_V1_BALANCE_H__
#define __CLIENT_API_V1_BALANCE_H__

#include <stdint.h>

#include "core/types.h"

typedef struct {
  byte_t addr[32];
  uint16_t maxResults;
  uint16_t count;
  int64_t balance;
} res_balance_t;

#endif  // __CLIENT_API_V1_BALANCE_H__
