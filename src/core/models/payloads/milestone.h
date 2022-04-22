// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_MILESTONE_H__
#define __CORE_MODELS_PL_MILESTONE_H__

#include <stdint.h>

#include "core/types.h"
#include "core/utils/byte_buffer.h"
#include "crypto/iota_crypto.h"
#include "utarray.h"

/**
 * @brief PoW milestone option object
 *
 */
typedef struct {
  uint32_t
      next_pow_score;  // The new PoW score all messages should adhere to. If 0 then the PoW score should not change.
  uint32_t next_pow_score_milestone_index;  // The index of the first milestone that will require a new minimal pow
                                            // score for applying transactions. This field comes into effect only if the
                                            // Next PoW Score field is not 0.
} milestone_pow_option_t;

/**
 * @brief Milestone options types
 *
 */
typedef enum {
  MILESTONE_OPTION_RECEIPTS = 0,  // Defines dynamic changes to the PoW parameters.
  MILESTONE_OPTION_POW,           // Defines UTXOs for newly migrated funds.
} milestone_option_e;

/**
 * @brief Milestone option object
 *
 */
typedef struct {
  milestone_option_e type;  ///< The type of milestone option.
  void *option;             ///< One of milestone options.
} milestone_option_t;

/**
 * @brief A list of milestone options
 *
 */
typedef struct milestone_options_list {
  milestone_option_t *option;           // Point to current milestone option
  struct milestone_options_list *next;  // Point to next milestone option
} milestone_options_list_t;

typedef struct {
  uint32_t type;       // payload type, set to 7 denotes a milestone payload
  uint32_t index;      // The index number of the milestone.
  uint32_t timestamp;  // The Unix time (seconds since Unix epoch) at which the milestone was issued.
  byte_t last_milestone_id[CRYPTO_BLAKE2B_256_HASH_BYTES];  // The milestone ID of the milestone with index number - 1
  UT_array *parents;                                        // Parents of milestone message.
  byte_t confirmed_merkle_root[CRYPTO_BLAKE2B_256_HASH_BYTES];  // The Merkle tree hash (BLAKE2b-256) of the message
                                                                // IDs of all messages confirmed by this milestone.
  byte_t applied_merkle_root[CRYPTO_BLAKE2B_256_HASH_BYTES];    // The Merkle tree hash (BLAKE2b-256) of the message IDs
                                                              // of all messages applied by this milestone that contain
                                                              // a state-mutating transaction.
  byte_buf_t *metadata;               // Binary data only relevant to milestone issuer, e.g. internal state.
  milestone_options_list_t *options;  // Milestone options: PoW milestone option or Receipts milestone option
  UT_array *signatures;  // The Ed25519 signature signing the BLAKE2b-256 hash of the serialized Milestone Essence. The
                         // signatures must be in the same order as the specified public keys.
} milestone_payload_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a milestone payload object
 *
 * @return milestone_payload_t*
 */
milestone_payload_t *milestone_payload_new();

/**
 * @brief Free a milestone payload object
 *
 * @param[in] ms A milestone object
 */
void milestone_payload_free(milestone_payload_t *ms);

/**
 * @brief Get parents count in a milestone
 *
 * @param[in] ms The milestone object
 * @return size_t
 */
size_t milestone_payload_get_parents_count(milestone_payload_t *ms);

/**
 * @brief Get a parent string from a milestone at index
 *
 * @param[in] ms The milestone object
 * @param[in] index The index of parent
 * @return byte_t* NULL on failed.
 */
byte_t *milestone_payload_get_parent(milestone_payload_t *ms, size_t index);

/**
 * @brief Get signatures count in a milestone
 *
 * @param[in] ms The milestone object
 * @return size_t
 */
size_t milestone_payload_get_signatures_count(milestone_payload_t *ms);

/**
 * @brief Get a signature string from a milestone at index
 *
 * @param[in] ms The milestone object
 * @param[in] index The index of signature
 * @return byte_t* NULL on failed.
 */
byte_t *milestone_payload_get_signature(milestone_payload_t *ms, size_t index);

/**
 * @brief Print out a milestone milestone
 *
 * @param[in] ms The milestone object
 * @param[in] indentation Tab indentation when printing milestone payload
 */
void milestone_payload_print(milestone_payload_t *ms, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
