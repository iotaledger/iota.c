// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_MILESTONE_H__
#define __CORE_MODELS_PL_MILESTONE_H__

#include <stdint.h>

#include "core/types.h"

typedef struct {
  payload_t type;  // Must be set to 1
  uint64_t index;  // The index number of the milestone.
  uint64_t
      timestamp;  // The Unix timestamp at which the milestone was issued. The unix timestamp is specified in seconds.
  byte_t inclusion_merkle_proof[64];  // Specifies the merkle proof which is computed out of all the tail transaction
                                      // hashes of all the newly confirmed state-mutating bundles.
  byte_t signature[64];  // The signature signing the entire message excluding the nonce and the signature itself.
} milestone_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
