#ifndef __CLIENT_API_V1_BALANCE_H__
#define __CLIENT_API_V1_BALANCE_H__

#include <stdint.h>

#include "core/address.h"
#include "core/types.h"

typedef struct {
  byte_t addr[IOTA_ADDRESS_BYTES];
  uint16_t maxResults;
  uint16_t count;
  int64_t balance;
} res_balance_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets balance from address
 *
 * @param[in] addr The address
 * @param[out] res A response object of balance info
 * @return int 0 on success
 */
int get_balance(byte_t addr[32], res_balance_t *res);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_V1_BALANCE_H__
