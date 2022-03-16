// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_INPUTS_UTXO_INPUT_H__
#define __CORE_MODELS_INPUTS_UTXO_INPUT_H__

#include <stdint.h>

#include "core/models/message.h"
#include "core/models/outputs/outputs.h"
#include "core/types.h"
#include "crypto/iota_crypto.h"

// Maximum number of inputs in a transaction payload.
#define UTXO_INPUT_MAX_COUNT 128
// Transaction ID bytes
#define IOTA_TRANSACTION_ID_BYTES 32
// OUTPUT ID bytes = 34 (IOTA_TRANSACTION_ID + OUTPUT INDEX)
#define IOTA_OUTPUT_ID_BYTES (IOTA_TRANSACTION_ID_BYTES + sizeof(uint16_t))

/**
 * @brief UTXO input structure
 *
 */
typedef struct {
  uint8_t input_type;                       ///< The input type. Set to value 0 to denote an UTXO Input.
  byte_t tx_id[IOTA_TRANSACTION_ID_BYTES];  ///< The BLAKE2b-256 hash of the transaction payload containing the
                                            ///< referenced output.
  uint16_t output_index;                    ///< The output index of the referenced output.
  utxo_output_t *output;                    ///< Unspent output object. It is needed for calculating inputs commitment.
  ed25519_keypair_t *keypair;               ///< optional, ed25519 keypair of this input
} utxo_input_t;

/**
 * @brief A list of utxo inputs
 *
 */
typedef struct utxo_inputs_list {
  utxo_input_t *input;            //< Points to a current input
  struct utxo_inputs_list *next;  //< Points to a next input
} utxo_inputs_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize an utxo input list.
 *
 * @return utxo_inputs_list_t* a NULL pointer
 */
utxo_inputs_list_t *utxo_inputs_new();

/**
 * @brief Free an utxo input list.
 *
 * @param[in] inputs An utxo input list.
 */
void utxo_inputs_free(utxo_inputs_list_t *inputs);

/**
 * @brief Append an utxo input element to the list.
 *
 * @param[in] inputs An utxo input list
 * @param[in] type An input type
 * @param[in] id A transaction ID
 * @param[in] index An output index of the referenced output
 * @param[in] key The ed25519 keypair of this input, optional
 * @return int 0 on success
 */
int utxo_inputs_add(utxo_inputs_list_t **inputs, uint8_t type, byte_t id[], uint16_t index, ed25519_keypair_t *key);

/**
 * @brief Get number of elements in an utxo input list
 *
 * @param[in] inputs An utxo input list.
 * @return uint16_t A count of elements
 */
uint16_t utxo_inputs_count(utxo_inputs_list_t *inputs);

/**
 * @brief Find an utxo input by a given transaction ID
 *
 * @param[in] inputs An utxo input hash table
 * @param[in] id A transaction ID
 * @return utxo_input_t*
 */
utxo_input_t *utxo_inputs_find_by_id(utxo_inputs_list_t *inputs, byte_t id[]);

/**
 * @brief Find an utxo input by a given index
 *
 * @param[in] inputs An utxo input hash table
 * @param[in] index An output index
 * @return utxo_input_t*
 */
utxo_input_t *utxo_inputs_find_by_index(utxo_inputs_list_t *inputs, uint16_t index);

/**
 * @brief Get length of a serialized utxo input list
 *
 * @param[in] inputs A list of utxo inputs
 * @return size_t The number of bytes of a serialized data
 */
size_t utxo_inputs_serialize_len(utxo_inputs_list_t *inputs);

/**
 * @brief Serialize inputs to a buffer
 *
 * @param[in] inputs An utxo input list
 * @param[out] buf A buffer for serialization
 * @param[in] buf_len The length of buffer
 * @return size_t number of bytes written to the buffer
 */
size_t utxo_inputs_serialize(utxo_inputs_list_t *inputs, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize binary data to a utxo input list object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return utxo_inputs_list_t* The deserialized utxo input list, NULL on errors
 */
utxo_inputs_list_t *utxo_inputs_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Print an utxo input list.
 *
 * @param[in] inputs An utxo input list.
 * @param[in] indentation Tab indentation when printing utxo output list
 */
void utxo_inputs_print(utxo_inputs_list_t *inputs, uint8_t indentation);

/**
 * @brief UTXO Inputs syntactic validation
 *
 * @param[in] inputs A list of UTXO input
 * @return true Valid
 * @return false Invalid
 */
bool utxo_inputs_syntactic(utxo_inputs_list_t *inputs);

#ifdef __cplusplus
}
#endif

#endif
