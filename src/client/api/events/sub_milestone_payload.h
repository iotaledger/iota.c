// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MILESTONE_LATEST_H__
#define __SUB_MILESTONE_LATEST_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/utils/byte_buffer.h"
#include "crypto/iota_crypto.h"

/**
 * @brief Stores timestamp and index
 *
 */
typedef struct {
  uint32_t timestamp;                                  ///< The timestamp of milestone payload
  uint32_t index;                                      ///< The index of milestone payload
  byte_t milestone_id[CRYPTO_BLAKE2B_256_HASH_BYTES];  ///< The milestone id
} events_milestone_payload_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Parse milestone payload response
 * @param[in] data Response data to parse
 * @param[out] res Parsed response object
 * @return int 0 If success
 */
int parse_milestone_payload(char *data, events_milestone_payload_t *res);

#ifdef __cplusplus
}
#endif

#endif