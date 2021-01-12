#ifndef __CORE_MODELS_OUTPUTS_SIG_UNLOCK_H__
#define __CORE_MODELS_OUTPUTS_SIG_UNLOCK_H__

#include <stdint.h>

#include "core/address.h"
#include "core/types.h"
#include "uthash.h"

// Serialized bytes = output type(uint8_t) + ed25519 address(32bytes) + amount(uint64_t)
#define UTXO_OUTPUT_SERIALIZED_BYTES (1 + ED25519_ADDRESS_BYTES + 8)

/**
 * @brief stores deposit outputs in a hash table
 *
 */
typedef struct {
  byte_t address[ED25519_ADDRESS_BYTES];  // Ed25519 address
  uint64_t amount;                        // The amount of tokens to deposit with this SigLockedSingleOutput output.
  UT_hash_handle hh;
} sig_unlocked_outputs_ht;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize an utxo output hash table.
 *
 * @return sig_unlocked_outputs_ht* a NULL pointer
 */
static sig_unlocked_outputs_ht *utxo_outputs_new() { return NULL; }

/**
 * @brief Find an utxo output by a given address
 *
 * @param[in] ht An utxo output hash table
 * @param[in] addr An address for searching
 * @return sig_unlocked_outputs_ht*
 */
static sig_unlocked_outputs_ht *utxo_outputs_find_by_addr(sig_unlocked_outputs_ht **ht, byte_t addr[]) {
  sig_unlocked_outputs_ht *elm = NULL;
  HASH_FIND(hh, *ht, addr, ED25519_ADDRESS_BYTES, elm);
  return elm;
}

/**
 * @brief Get the size of utxo outputs
 *
 * @param[in] ht An utxo output hash table.
 * @return uint8_t
 */
static uint8_t utxo_outputs_count(sig_unlocked_outputs_ht **ht) { return (uint8_t)HASH_COUNT(*ht); }

/**
 * @brief Free an utxo output hash table.
 *
 * @param[in] utxo_ins An utxo output hash table.
 */
static void utxo_outputs_free(sig_unlocked_outputs_ht **ht) {
  sig_unlocked_outputs_ht *curr_elm, *tmp;
  HASH_ITER(hh, *ht, curr_elm, tmp) {
    HASH_DEL(*ht, curr_elm);
    free(curr_elm);
  }
}

/**
 * @brief Append an utxo output element to the table.
 *
 * @param[in] ht An utxo output hash table
 * @param[in] addr An ED25519 address
 * @param[in] amount The amount of tokens to deposit
 * @return int 0 on success
 */
int utxo_outputs_add(sig_unlocked_outputs_ht **ht, byte_t addr[], uint64_t amount);

/**
 * @brief Serialize outputs to a buffer
 *
 * @param[in] ht An utxo output hash table
 * @param[out] buf A buffer for serialization
 * @return size_t number of bytes write to the buffer
 */
size_t utxo_outputs_serialization(sig_unlocked_outputs_ht **ht, byte_t buf[]);

/**
 * @brief Print an utxo output hash table.
 *
 * @param[in] ht An utxo output hash table.
 */
void utxo_outputs_print(sig_unlocked_outputs_ht **ht);

#ifdef __cplusplus
}
#endif

#endif