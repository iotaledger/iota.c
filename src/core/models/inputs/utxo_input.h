// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_INPUTS_UTXO_INPUT_H__
#define __CORE_MODELS_INPUTS_UTXO_INPUT_H__

#include <stdint.h>

#include "core/address.h"
#include "core/models/message.h"
#include "core/types.h"
#include "crypto/iota_crypto.h"

// Maximum number of inputs in a transaction payload.
#define UTXO_INPUT_MAX_COUNT 128

/**
 * @brief UTXO input structure
 *
 */
typedef struct {
  uint8_t input_type;                       ///< The input type. Set to value 0 to denote an UTXO Input.
  byte_t tx_id[IOTA_TRANSACTION_ID_BYTES];  ///< The BLAKE2b-256 hash of the transaction payload containing the
                                            ///< referenced output.
  uint16_t output_index;                    ///< The output index of the referenced output.
} utxo_input_t;

/**
 * @brief A list of UTXO inputs
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
 * @brief Initialize an UTXO input list.
 *
 * @return a NULL pointer
 */
utxo_inputs_list_t *utxo_inputs_new();

/**
 * @brief Free an UTXO input list.
 *
 * @param[in] inputs An UTXO input list.
 */
void utxo_inputs_free(utxo_inputs_list_t *inputs);

/**
 * @brief Append an UTXO input element to the list.
 *
 * @param[in] inputs An UTXO input list
 * @param[in] type An input type
 * @param[in] id A transaction ID
 * @param[in] index An output index of the referenced output
 * @return int 0 on success
 */
int utxo_inputs_add(utxo_inputs_list_t **inputs, uint8_t type, byte_t id[], uint16_t index);

/**
 * @brief Get number of elements in an utxo input list
 *
 * @param[in] inputs An UTXO input list.
 * @return uint16_t A count of elements
 */
uint16_t utxo_inputs_count(utxo_inputs_list_t *inputs);

/**
 * @brief Find an UTXO input by a given transaction ID
 *
 * @param[in] inputs An UTXO input hash table
 * @param[in] id A transaction ID
 * @return utxo_input_t* or NULL for not found
 */
utxo_input_t *utxo_inputs_find_by_id(utxo_inputs_list_t *inputs, byte_t id[]);

/**
 * @brief Find an UTXO input by a given index
 *
 * @param[in] inputs An UTXO input hash table
 * @param[in] index An output index
 * @return utxo_input_t* or NULL for not found
 */
utxo_input_t *utxo_inputs_find_by_index(utxo_inputs_list_t *inputs, uint16_t index);

/**
 * @brief Get the length of a serialized UTXO input list
 *
 * @param[in] inputs A list of UTXO inputs
 * @return size_t The number of bytes of a serialized data
 */
size_t utxo_inputs_serialize_len(utxo_inputs_list_t *inputs);

/**
 * @brief Serialize an UTXO input list to a buffer
 *
 * @param[in] inputs An UTXO input list
 * @param[out] buf A buffer for serialization
 * @param[in] buf_len The length of buffer
 * @return size_t number of bytes written to the buffer
 */
size_t utxo_inputs_serialize(utxo_inputs_list_t *inputs, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize binary data to a UTXO input list object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return utxo_inputs_list_t* The deserialized UTXO input list, NULL on errors
 */
utxo_inputs_list_t *utxo_inputs_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Print an UTXO input list.
 *
 * @param[in] inputs An UTXO input list.
 * @param[in] indentation Tab indentation when printing utxo output list
 */
void utxo_inputs_print(utxo_inputs_list_t *inputs, uint8_t indentation);

/**
 * @brief UTXO inputs syntactic validation
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
