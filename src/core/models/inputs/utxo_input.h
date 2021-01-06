#ifndef __CORE_MODELS_INPUTS_UTXO_INPUT_H__
#define __CORE_MODELS_INPUTS_UTXO_INPUT_H__

#include <stdint.h>

#include "core/types.h"
#include "uthash.h"

#define TRANSACTION_ID_BYTES 32

typedef struct {
  byte_t tx_id[TRANSACTION_ID_BYTES];  // The transaction reference from which the UTXO comes from.
  uint8_t output_index;                // The index of the output on the referenced transaction to consume 0<= x < 127.
  UT_hash_handle hh;
} utxo_input_ht;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize an utxo input hash table.
 *
 * @return utxo_inputs_t* a NULL pointer
 */
static utxo_input_ht *utxo_inputs_new() { return NULL; }

/**
 * @brief Find an utxo input by a given transaction ID
 *
 * @param[in] inputs An utxo input hash table
 * @param[in] tx_id A transaction ID
 * @return utxo_input_ht*
 */
static utxo_input_ht *utxo_inputs_find_by_id(utxo_input_ht **inputs, byte_t tx_id[]) {
  utxo_input_ht *in = NULL;
  HASH_FIND(hh, *inputs, tx_id, TRANSACTION_ID_BYTES, in);
  return in;
}

/**
 * @brief Get the size of utxo inputs
 *
 * @param[in] ht An utxo input hash table.
 * @return uint8_t
 */
static uint8_t utxo_inputs_count(utxo_input_ht **ht) { return (uint8_t)HASH_COUNT(*ht); }

/**
 * @brief Free an utxo input hash table.
 *
 * @param[in] utxo_ins An utxo input hash table.
 */
static void utxo_inputs_free(utxo_input_ht **ht) {
  utxo_input_ht *curr_elm, *tmp;
  HASH_ITER(hh, *ht, curr_elm, tmp) {
    HASH_DEL(*ht, curr_elm);
    free(curr_elm);
  }
}

/**
 * @brief Append an utxo input element to the list.
 *
 * @param[in] inputs An input hash table
 * @param[in] tx_id A transaction ID
 * @param[in] index An index
 * @return int 0 on success
 */
int utxo_inputs_add(utxo_input_ht **inputs, byte_t tx_id[], uint8_t index);

/**
 * @brief Print an utxo input hash table.
 *
 * @param[in] inputs An utxo input hash table.
 */
void utxo_inputs_print(utxo_input_ht **inputs);

#ifdef __cplusplus
}
#endif

#endif