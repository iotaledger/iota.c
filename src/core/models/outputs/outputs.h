// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUTS_H__
#define __CORE_MODELS_OUTPUTS_H__

#include <stdint.h>

#include "core/address.h"
#include "core/types.h"
#include "uthash.h"

// Serialized bytes = output type(uint8_t) + address type(uint8_t) + ed25519 address(32bytes) + amount(uint64_t)
#define UTXO_OUTPUT_SERIALIZED_BYTES (1 + 1 + ED25519_ADDRESS_BYTES + 8)

/**
 * @brief Output types
 *
 * SigLockedSingleOutput: Describes a deposit to a single address which is unlocked via a signature
 * SigLockedDustAllowanceOutput: enables an address to receive dust outputs. It can be consumed as an input like a
 * regular SigLockedSingleOutput
 *
 * The amount of a SigLockedDustAllowanceOutput must be at least 1 Mi. Apart from this, SigLockedDustAllowanceOutputs
 * are processed identical to SigLockedSingleOutput
 *
 */
typedef enum {
  OUTPUT_SINGLE_OUTPUT = 0,  ///< SigLockedSingleOutput
  OUTPUT_DUST_ALLOWANCE      ///< SigLockedDustAllowanceOutput
} output_type_t;

/**
 * @brief Stores deposit outputs in a hash table
 *
 */
typedef struct {
  uint8_t output_type;                    ///< 0: SigLockedSingleOutput, 1: SigLockedDustAllowanceOutput
  byte_t address[ED25519_ADDRESS_BYTES];  ///< Ed25519 address
  uint64_t amount;                        ///< The amount of tokens to deposit with this output.
  UT_hash_handle hh;
} outputs_ht;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize an utxo output hash table.
 *
 * @return outputs_ht* a NULL pointer
 */
static outputs_ht *utxo_outputs_new() { return NULL; }

/**
 * @brief Find an utxo output by a given address
 *
 * @param[in] ht An utxo output hash table
 * @param[in] addr An address for searching
 * @return outputs_ht*
 */
static outputs_ht *utxo_outputs_find_by_addr(outputs_ht **ht, byte_t addr[]) {
  outputs_ht *elm = NULL;
  HASH_FIND(hh, *ht, addr, ED25519_ADDRESS_BYTES, elm);
  return elm;
}

/**
 * @brief Get the size of utxo outputs
 *
 * @param[in] ht An utxo output hash table.
 * @return uint16_t
 */
static uint16_t utxo_outputs_count(outputs_ht **ht) { return (uint16_t)HASH_COUNT(*ht); }

/**
 * @brief Free an utxo output hash table.
 *
 * @param[in] utxo_ins An utxo output hash table.
 */
static void utxo_outputs_free(outputs_ht **ht) {
  outputs_ht *curr_elm, *tmp;
  HASH_ITER(hh, *ht, curr_elm, tmp) {
    HASH_DEL(*ht, curr_elm);
    free(curr_elm);
  }
}

/**
 * @brief Append an utxo output element to the table.
 *
 * @param[in] ht An utxo output hash table
 * @param[in] type output type
 * @param[in] addr An ED25519 address
 * @param[in] amount The amount of tokens to deposit
 * @return int 0 on success
 */
int utxo_outputs_add(outputs_ht **ht, output_type_t type, byte_t addr[], uint64_t amount);

/**
 * @brief Serialize outputs to a buffer
 *
 * @param[in] ht An utxo output hash table
 * @param[out] buf A buffer for serialization
 * @return size_t number of bytes write to the buffer
 */
size_t utxo_outputs_serialization(outputs_ht **ht, byte_t buf[]);

/**
 * @brief Print an utxo output hash table.
 *
 * @param[in] ht An utxo output hash table.
 */
void utxo_outputs_print(outputs_ht **ht);

#ifdef __cplusplus
}
#endif

#endif