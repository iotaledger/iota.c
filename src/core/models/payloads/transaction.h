// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_TX_H__
#define __CORE_MODELS_PL_TX_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/address.h"
#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/sig_unlocked_single_output.h"
#include "core/types.h"

static const uint64_t MAX_IOTA_SUPPLY = 2779530283277761;

typedef struct {
  signature_t type;                      // Set to value 1 to denote an Ed25519 Signature
  byte_t pub_key[ED_PUBLIC_KEY_BYTES];   // The public key of the Ed25519 keypair which is used to verify the signature.
  byte_t signature[ED_SIGNATURE_BYTES];  // The signature signing the serialized Unsigned Transaction.
} ed25519_signature_t;

/**
 * @brief An unlock block list object
 *
 */
typedef struct unlock_blocks {
  unlock_block_t type;            // 0 to denote a Signature Unlock Block, 1 for a Reference Unlock Block.
  ed25519_signature_t signature;  // For signature unlock block, public key and signature for a specific input.
  uint16_t reference;             // For reverence unlock block, the index of a previous unlock block.
  struct unlock_blocks* prev;
  struct unlock_blocks* next;
} unlock_blocks_t;

/**
 * @brief Transaction Essence, the essence data making up a transaction by defining its inputs and outputs and an
 * optional payload.
 *
 * Based on protocol design, we can have different types of input and output in a transaction.
 * At this moment, we have only utxo_input_ht for intput and SigLockedSingleOutput for output.
 *
 */
typedef struct {
  uint8_t tx_type;                   // Set to value 0 to denote a Transaction Essence.
  uint32_t payload_len;              // The length in bytes of the optional payload.
  utxo_input_ht* inputs;             // any of UTXO input
  sig_unlocked_outputs_ht* outputs;  // any of UTXO output
  void* payload;                     // an optional payload
} transaction_essence_t;

/**
 * @brief A Transaction payload is made up of two parts:
 * 1. The The Transaction Essence part which contains the inputs, outputs and an optional embedded payload.
 * 2. The Unlock Blocks which unlock the Transaction Essence's inputs. In case the unlock block contains a signature, it
 * signs the entire Transaction Essence part.
 *
 */
typedef struct {
  payload_t type;                  // Set to value 0 to denote a Transaction payload.
  uint32_t unlock_blocks_count;    // The count of unlock blocks proceeding. Must match count of inputs specified.
  transaction_essence_t* essence;  // Describes the essence data making up a transaction by defining its inputs and
                                   // outputs and an optional payload.
  void* unlock_blocks;             // Defines an unlock block containing signature(s) unlocking input(s).
} transaction_payload_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a transaction essence object
 *
 * @return transaction_essence_t*
 */
transaction_essence_t* tx_essence_new();

/**
 * @brief Add an input element to the essence
 *
 * @param[in] es An essence object
 * @param[in] tx_id A transaction ID
 * @param[in] index The index of the output on the referenced transaction to consume
 * @return int 0 on success
 */
int tx_essence_add_input(transaction_essence_t* es, byte_t tx_id[], uint8_t index);

/**
 * @brief Add an output element to the essence
 *
 * @param[in] es An essence object
 * @param[in] addr An ed25519 address
 * @param[in] amount The amount of tokens to deposit with this SigLockedSingleOutput output
 * @return int 0 on success
 */
int tx_essence_add_output(transaction_essence_t* es, byte_t addr[], uint64_t amount);

/**
 * @brief TODO: Add a payload to essence
 *
 * @param[in] es
 * @return int
 */
int tx_essence_add_payload(transaction_essence_t* es);

/**
 * @brief Serialize essence object
 *
 * @param[in] es An essence object
 * @param[out] len The length of serialized essence data
 * @return byte_t* serialized essence data, free is needed.
 */
byte_t* tx_essence_serialize(transaction_essence_t* es, size_t* len);

/**
 * @brief Free an essence object
 *
 * @param[in] es An essence object
 */
void tx_essence_free(transaction_essence_t* es);

/**
 * @brief Print out a transaction essence
 *
 * @param[in] es An essence object
 */
void tx_essence_print(transaction_essence_t* es);

/**
 * @brief Sort inputs and outputs in lexicographical order
 *
 * @param[in] es An essence object
 */
void tx_essence_sort_input_output(transaction_essence_t* es);

/**
 * @brief Initialize a block list object
 *
 * @return unlock_blocks_t* a NULL pointer
 */
unlock_blocks_t* tx_block_new();

/**
 * @brief Add a signature block
 *
 * @param[in] blocks The head of list
 * @param[in] sig A ed25519 signature object
 * @return int 0 on success
 */
int tx_block_add_signature(unlock_blocks_t** blocks, ed25519_signature_t* sig);

/**
 * @brief Add a reference block
 *
 * @param[in] blocks The head of list
 * @param[in] ref The index of reference
 * @return int 0 on success.
 */
int tx_block_add_reference(unlock_blocks_t** blocks, uint16_t ref);

/**
 * @brief Get the length of unlock blocks
 *
 * @param[in] blocks The head of list
 * @return uint16_t
 */
uint16_t tx_block_count(unlock_blocks_t* blocks);

/**
 * @brief Serialize unlock blocks
 *
 * @param[in] blocks The head of list
 * @param[out] len The length of serialized data
 * @return byte_t* A pointer to serialized data, free is needed.
 */
byte_t* tx_block_serialize(unlock_blocks_t* blocks, size_t* len);

/**
 * @brief Free an unlock block list
 *
 * @param blocks An unlock block object
 */
void tx_block_free(unlock_blocks_t* blocks);

void tx_payload_new();
void tx_payload_add_input();
void tx_payload_add_output();
void tx_payload_add_unlock_block();
void tx_payload_serialize();
void tx_payload_free();

#ifdef __cplusplus
}
#endif

#endif
