// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_TX_H__
#define __CORE_MODELS_PL_TX_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/address.h"
#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/outputs.h"
#include "core/models/payloads/indexation.h"
#include "core/models/unlock_block.h"
#include "core/types.h"

static const uint64_t MAX_IOTA_SUPPLY = 2779530283277761;

/**
 * @brief Transaction Essence, the essence data making up a transaction by defining its inputs and outputs and an
 * optional payload.
 *
 * Based on protocol design, we can have different types of input and output in a transaction.
 * At this moment, we have only utxo_input_ht for intput and SigLockedSingleOutput for output.
 *
 */
typedef struct {
  uint8_t tx_type;        ///< Set to value 0 to denote a Transaction Essence.
  uint32_t payload_len;   ///< The length in bytes of the optional payload.
  utxo_input_ht* inputs;  ///< any of UTXO input
  outputs_ht* outputs;    ///< any of UTXO output
  void* payload;          ///< an indexation payload at this moment
} transaction_essence_t;

/**
 * @brief A Transaction payload is made up of two parts:
 * 1. The The Transaction Essence part which contains the inputs, outputs and an optional embedded payload.
 * 2. The Unlock Blocks which unlock the Transaction Essence's inputs. In case the unlock block contains a signature, it
 * signs the entire Transaction Essence part.
 *
 */
typedef struct {
  payload_t type;                  ///< Set to value 0 to denote a Transaction payload.
  transaction_essence_t* essence;  ///< Describes the essence data making up a transaction by defining its inputs and
                                   ///< outputs and an optional payload.
  unlock_blocks_t* unlock_blocks;  ///< Defines an unlock block containing signature(s) unlocking input(s).
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
 * @brief Add an input to the essence with ed25519 key pair
 *
 * @param[in] es An essence object
 * @param[in] tx_id A transaction ID
 * @param[in] index The index of the output
 * @param[in] pub A ed25519 public key
 * @param[in] priv A ed25519 private key
 * @return int 0 on success
 */
int tx_essence_add_input_with_key(transaction_essence_t* es, byte_t const tx_id[], uint8_t index, byte_t const pub[],
                                  byte_t const priv[]);

/**
 * @brief Add an output element to the essence
 *
 * @param[in] es An essence object
 * @param[in] type The output type
 * @param[in] addr An ed25519 address
 * @param[in] amount The amount of tokens to deposit with this SigLockedSingleOutput output
 * @return int 0 on success
 */
int tx_essence_add_output(transaction_essence_t* es, output_type_t type, byte_t addr[], uint64_t amount);

/**
 * @brief Add a payload to essence
 *
 * support indexation payload at this moment, type = 2
 *
 * @param[in] es An essence object
 * @param[in] type A payload type
 * @param[in] payload A pointer to a payload object
 * @return int 0 on success
 */
int tx_essence_add_payload(transaction_essence_t* es, uint32_t type, void* payload);

/**
 * @brief Get the serialized length of the essence
 *
 * @param[in] es An essence object
 * @return size_t 0 on failed
 */
size_t tx_essence_serialize_length(transaction_essence_t* es);

/**
 * @brief Serialize essence object
 *
 * @param[in] es An essence object
 * @param[out] buf A buffer holds serialized data
 * @return size_t number of bytes written to the buffer
 */
size_t tx_essence_serialize(transaction_essence_t* es, byte_t buf[]);

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
 * @brief Allocate a tansaction payload object
 *
 * @return transaction_payload_t*
 */
transaction_payload_t* tx_payload_new();

/**
 * @brief Add an input to the transaction payload
 *
 * @param[in] tx A transaction payload object
 * @param[in] tx_id A transaction ID
 * @param[in] index The index of the output on the referenced transaction to consume
 * @return int 0 on success
 */
int tx_payload_add_input(transaction_payload_t* tx, byte_t tx_id[], uint8_t index);

/**
 * @brief Add an input with ed25519 keypair to the transaction payload
 *
 * @param[in] tx A transaction payload object
 * @param[in] tx_id A transaction ID
 * @param[in] index The index of the output on the referenced transaction to consume
 * @param[in] pub The public key
 * @param[in] priv The private key
 * @return int 0 on success
 */
int tx_payload_add_input_with_key(transaction_payload_t* tx, byte_t tx_id[], uint8_t index, byte_t const pub[],
                                  byte_t const priv[]);

/**
 * @brief Add an output to the transaction payload
 *
 * @param[in] tx A transaction payload
 * @param[in] type The output type
 * @param[in] addr An ed25519 address
 * @param[in] amount The amount of tokens to deposit with this SigLockedSingleOutput output
 * @return int 0 on success
 */
int tx_payload_add_output(transaction_payload_t* tx, output_type_t type, byte_t addr[], uint64_t amount);

/**
 * @brief Add a signature unlocked block to the transaction
 *
 * @param[in] tx A transaction payload
 * @param[in] sig_block An ed25519 signature block
 * @param[in] sig_len the length of ed25519 signature block
 * @return int 0 on success
 */
int tx_payload_add_sig_block(transaction_payload_t* tx, byte_t* sig_block, size_t sig_len);

/**
 * @brief Add a reference unlocked block to the transaction
 *
 * @param[in] tx A transaction payload
 * @param[in] ref The index of reference
 * @return int 0 on success
 */
int tx_payload_add_ref_block(transaction_payload_t* tx, uint16_t ref);

/**
 * @brief Get the length of a transaction payload
 *
 * @param[in] tx A transaction payload
 * @return size_t The number of bytes of serialized data
 */
size_t tx_payload_serialize_length(transaction_payload_t* tx);

/**
 * @brief Serialize a transaction payload
 *
 * @param[in] tx A transaction payload
 * @param[out] buf A buffer holds the serialized data
 * @return size_t number of bytes written to the buffer
 */
size_t tx_payload_serialize(transaction_payload_t* tx, byte_t buf[]);

/**
 * @brief Free a transaction payload object
 *
 * @param[in] tx A transaction payload
 */
void tx_payload_free(transaction_payload_t* tx);

/**
 * @brief Print out a transaction payload
 *
 * @param[in] tx A transaction payload
 */
void tx_payload_print(transaction_payload_t* tx);

#ifdef __cplusplus
}
#endif

#endif
