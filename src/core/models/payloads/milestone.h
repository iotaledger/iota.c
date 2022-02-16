// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_MILESTONE_H__
#define __CORE_MODELS_PL_MILESTONE_H__

#include <stdint.h>

#include "core/types.h"
#include "utarray.h"

// Milestone signature length in binary representation
#define MILESTONE_SIGNATURE_LEN 64

// Milestone signature length in binary representation
#define MILESTONE_PUBLIC_KEY_LEN 32

typedef struct {
  payload_t type;                   // Must be set to 1.
  uint32_t index;                   // The index number of the milestone.
  uint64_t timestamp;               // The Unix time (seconds since Unix epoch) at which the milestone was issued.
  UT_array *parents;                // Parents of milestone message.
  char inclusion_merkle_proof[64];  // The Merkle tree hash (BLAKE2b-256) of the message IDs of all the not-ignored
                                    // state-mutating transaction payloads referenced by the milestone.
  uint32_t
      next_pow_score;  // The new PoW score all messages should adhere to. If 0 then the PoW score should not change.
  uint32_t next_pow_score_milestone_index;  // The index of the first milestone that will require a new minimal pow
                                            // score for applying transactions. This field comes into effect only if the
                                            // Next PoW Score field is not 0.
  UT_array *pub_keys;                       // Ed25519 Public Keys
  void *receipt;                            // TODO implement this
  UT_array *signatures;  // The Ed25519 signature signing the BLAKE2b-256 hash of the serialized Milestone Essence. The
                         // signatures must be in the same order as the specified public keys.
} milestone_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a milestone payload object
 *
 * @return milestone_t*
 */
milestone_t *milestone_payload_new();

/**
 * @brief Free a milestone payload object
 *
 * @param[in] ms A milestone object
 */
void milestone_payload_free(milestone_t *ms);

/**
 * @brief Get parents count in a milestone
 *
 * @param[in] ms The milestone object
 * @return size_t
 */
size_t milestone_payload_get_parents_count(milestone_t *ms);

/**
 * @brief Get a parent string from a milestone at index
 *
 * @param[in] ms The milestone object
 * @param[in] index The index of parent
 * @return byte_t* NULL on failed.
 */
byte_t *milestone_payload_get_parent(milestone_t *ms, size_t index);

/**
 * @brief Get keys count in a milestone
 *
 * @param[in] ms The milestone object
 * @return size_t
 */
size_t milestone_payload_get_pub_keys_count(milestone_t *ms);

/**
 * @brief Get a key string from a milestone at index
 *
 * @param[in] ms The milestone object
 * @param[in] index The index of key
 * @return byte_t* NULL on failed.
 */
byte_t *milestone_payload_get_pub_key(milestone_t *ms, size_t index);

/**
 * @brief Get signature count in a milestone
 *
 * @param[in] ms The milestone object
 * @return size_t
 */
size_t milestone_payload_get_signatures_count(milestone_t *ms);

/**
 * @brief Get a signature string from a milestone at index
 *
 * @param[in] ms The milestone object
 * @param[in] index The index of signature
 * @return byte_t* NULL on failed.
 */
byte_t *milestone_payload_get_signature(milestone_t *ms, size_t index);

/**
 * @brief Print out a milestone milestone
 *
 * @param[in] ms The milestone object
 * @param[in] indentation Tab indentation when printing milestone payload
 */
void milestone_payload_print(milestone_t *ms, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
