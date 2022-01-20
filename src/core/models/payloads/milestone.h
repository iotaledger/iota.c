// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_MILESTONE_H__
#define __CORE_MODELS_PL_MILESTONE_H__

#include <stdint.h>

#include "core/types.h"
#include "utarray.h"

// TODO update milestone structure: https://github.com/iotaledger/protocol-rfcs/pull/19
typedef struct {
  payload_t type;  // Must be set to 1
  uint64_t index;  // The index number of the milestone.
  uint64_t
      timestamp;  // The Unix timestamp at which the milestone was issued. The unix timestamp is specified in seconds.
  char inclusion_merkle_proof[64];  // Specifies the merkle proof which is computed out of all the tail transaction
                                    // hashes of all the newly confirmed state-mutating bundles.
  UT_array *signatures;  // The signature signing the entire message excluding the nonce and the signature itself.
} milestone_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a milestone payload object
 *
 * @return milestone_t*
 */
milestone_t *payload_milestone_new();

/**
 * @brief Free a milestone payload object
 *
 * @param[in] ms A milestone object
 */
void payload_milestone_free(milestone_t *ms);

#ifdef __cplusplus
}
#endif

#endif
