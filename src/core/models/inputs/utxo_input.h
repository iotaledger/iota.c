// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_INPUTS_UTXO_INPUT_H__
#define __CORE_MODELS_INPUTS_UTXO_INPUT_H__

#include <stdint.h>

#include "core/types.h"
#include "crypto/iota_crypto.h"
#include "uthash.h"

#define TRANSACTION_ID_BYTES 32
// Serialized bytes = input type(uint8_t) + transaction id(32bytes) + index(uint16_t)
#define UTXO_INPUT_SERIALIZED_BYTES (1 + TRANSACTION_ID_BYTES + 2)

/**
 * @brief ED25519 keypair structure
 *
 */
typedef struct {
  byte_t
      pub_key[ED_PUBLIC_KEY_BYTES];   ///< The public key of the Ed25519 keypair which is used to verify the signature.
  byte_t priv[ED_PRIVATE_KEY_BYTES];  ///< The private key for signing the serialized Unsigned Transaction.
} ed25519_keypair_t;

/**
 * @brief UTXO input structure
 *
 */
typedef struct {
  byte_t tx_id[TRANSACTION_ID_BYTES];  ///< The transaction reference from which the UTXO comes from.
  uint16_t output_index;      ///< The index of the output on the referenced transaction to consume 0<= x < 127.
  ed25519_keypair_t keypair;  ///< ed25519 keypair of this input
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
static utxo_input_ht *utxo_inputs_find_by_id(utxo_input_ht **inputs, byte_t const tx_id[]) {
  utxo_input_ht *in = NULL;
  HASH_FIND(hh, *inputs, tx_id, TRANSACTION_ID_BYTES, in);
  return in;
}

/**
 * @brief Get the size of utxo inputs
 *
 * @param[in] ht An utxo input hash table.
 * @return uint16_t
 */
static uint16_t utxo_inputs_count(utxo_input_ht **ht) { return (uint16_t)HASH_COUNT(*ht); }

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
int utxo_inputs_add(utxo_input_ht **inputs, byte_t tx_id[], uint16_t index);

/**
 * @brief Append an utxo input with keypair to hash table
 *
 * @param[in] inputs An input hash table
 * @param[in] tx_id A transaction ID
 * @param[in] index An index
 * @param[in] pub An ed25519 public key
 * @param[in] priv An ed25519 private key
 * @return int 0 on success
 */
int utxo_inputs_add_with_key(utxo_input_ht **inputs, byte_t const tx_id[], uint16_t index, byte_t const pub[],
                             byte_t const priv[]);

/**
 * @brief Serialize inputs to a buffer
 *
 * @param[in] inputs An utxo input hash table
 * @param[out] buf A buffer for serialization
 * @return size_t number of bytes write to the buffer
 */
size_t utxo_inputs_serialization(utxo_input_ht **inputs, byte_t buf[]);

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