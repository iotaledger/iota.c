// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_PL_TX_H__
#define __CORE_MODELS_PL_TX_H__

#include <stdint.h>
#include <stdlib.h>

#include "core/address.h"
#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/outputs.h"
#include "core/models/unlock_block.h"

/**
 * @brief Transaction Essence, the essence data making up a transaction by defining its inputs and outputs and an
 * optional payload.
 *
 * Based on protocol design, we can have different types of input and output in a transaction.
 * At this moment, we have only utxo_input_list for input.
 * For output we have basic, alias, foundry and nft output.
 *
 */
typedef struct {
  uint8_t tx_type;      ///< Set to value 1 to denote a Transaction Essence.
  uint64_t network_id;  ///< Network identifier. It is first 8 bytes of the `BLAKE2b-256` hash of the network name
                        ///< (identifier string of the network).
  utxo_inputs_list_t* inputs;                               ///< An UTXO input list.
  byte_t inputs_commitment[CRYPTO_BLAKE2B_256_HASH_BYTES];  ///< BLAKE2b-256 hash of the serialized outputs referenced
                                                            ///< in Inputs by their Output IDs (Transaction ID ||
                                                            ///< Transaction Output Index).
  utxo_outputs_list_t* outputs;                             ///< An UTXO output list.
  uint32_t payload_len;                                     ///< The length in bytes of the optional payload.
  void* payload;                                            ///< An tagged data payload at this moment.
} transaction_essence_t;

/**
 * @brief A Transaction payload is made up of two parts:
 * 1. The The Transaction Essence part which contains the inputs, outputs and an optional embedded payload.
 * 2. The Unlock Blocks which unlock the Transaction Essence's inputs. In case the unlock block contains a signature, it
 * signs the entire Transaction Essence part.
 *
 */
typedef struct {
  uint32_t type;                   ///< Set to value 6 to denote a Transaction payload.
  transaction_essence_t* essence;  ///< Describes the essence data making up a transaction by defining its inputs and
                                   ///< outputs and an optional payload.
  unlock_list_t* unlock_blocks;    ///< Defines a list of unlock blocks (signature, reference, alias, NFT) which unlock
                                   ///< the inputs of the transaction essence.
} transaction_payload_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a transaction essence object
 *
 * @param[in] network_id A network ID
 * @return transaction_essence_t*
 */
transaction_essence_t* tx_essence_new(uint64_t network_id);

/**
 * @brief Free an essence object
 *
 * @param[in] es An essence object
 */
void tx_essence_free(transaction_essence_t* es);

/**
 * @brief Add an input element to the essence
 *
 * @param[in] es An essence object
 * @param[in] type An input type
 * @param[in] tx_id A transaction ID
 * @param[in] index The index of the output of the referenced transaction
 * @return int 0 on success
 */
int tx_essence_add_input(transaction_essence_t* es, uint8_t type, byte_t tx_id[], uint8_t index);

/**
 * @brief Add an output element to the essence
 *
 * @param[in] es An essence object
 * @param[in] type An output type
 * @param[in] output Pointer to an output
 * @return int 0 on success
 */
int tx_essence_add_output(transaction_essence_t* es, utxo_output_type_t type, void* output);

/**
 * @brief Add a payload to essence
 *
 * support tagged data payload at this moment
 *
 * @param[in] es An essence object
 * @param[in] type A payload type
 * @param[in] payload A pointer to a payload object
 * @return int 0 on success
 */
int tx_essence_add_payload(transaction_essence_t* es, uint32_t type, void* payload);

/**
 * @brief Calculate inputs commitment for transaction essence
 *
 * @param[in] es An essence object
 * @param[in] unspent_outputs List of unspent outputs which will be used as transaction inputs
 * @return int 0 on success
 */
int tx_essence_inputs_commitment_calculate(transaction_essence_t* es, utxo_outputs_list_t* unspent_outputs);

/**
 * @brief Get the serialized length of the essence
 *
 * @param[in] es An essence object
 * @return size_t The number of bytes of a serialized data
 */
size_t tx_essence_serialize_length(transaction_essence_t* es);

/**
 * @brief Serialize an essence object
 *
 * @param[in] es An essence object
 * @param[out] buf A buffer to hold the serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t number of bytes written to the buffer
 */
size_t tx_essence_serialize(transaction_essence_t* es, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize binary data to a transaction essence object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return transaction_essence_t* The deserialized txn essence, NULL on errors
 */
transaction_essence_t* tx_essence_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Transaction Essence syntactic validation
 *
 * @param[in] es An essence object
 * @param[in] byte_cost The Byte Cost configure
 * @return true Valid
 * @return false Invalid
 */
bool tx_essence_syntactic(transaction_essence_t* es, byte_cost_config_t* byte_cost);

/**
 * @brief Print out a transaction essence
 *
 * @param[in] es An essence object
 * @param[in] indentation Tab indentation when printing transaction essence
 */
void tx_essence_print(transaction_essence_t* es, uint8_t indentation);

/**
 * @brief Allocate a transaction payload object
 *
 * @param[in] network_id A network ID
 * @return transaction_payload_t*
 */
transaction_payload_t* tx_payload_new(uint64_t network_id);

/**
 * @brief Free a transaction payload object
 *
 * @param[in] tx A transaction payload
 */
void tx_payload_free(transaction_payload_t* tx);

/**
 * @brief Get the serialized length of a transaction payload
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
 * @param[in] buf_len The length of buffer
 * @return size_t number of bytes written to the buffer
 */
size_t tx_payload_serialize(transaction_payload_t* tx, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize binary data to a transaction payload object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return transaction_payload_t* The deserialized tx payload, NULL on errors
 */
transaction_payload_t* tx_payload_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Calculate and return transaction payload ID
 *
 * @param[in] tx A transaction payload
 * @param[out] id Calculated transaction payload ID
 * @param[in] id_len Length of transaction payload ID array
 * @return int 0 on success
 */
int tx_payload_calculate_id(transaction_payload_t* tx, byte_t id[], uint8_t id_len);

/**
 * @brief Print out a transaction payload
 *
 * @param[in] tx A transaction payload
 * @param[in] indentation Tab indentation when printing transaction payload
 */
void tx_payload_print(transaction_payload_t* tx, uint8_t indentation);

/**
 * @brief Transaction payload syntactic validation
 *
 * @param[in] tx A transaction payload
 * @param[in] byte_cost The Byte Cost configure
 * @return true Valid
 * @return false Invalid
 */
bool tx_payload_syntactic(transaction_payload_t* tx, byte_cost_config_t* byte_cost);

#ifdef __cplusplus
}
#endif

#endif
