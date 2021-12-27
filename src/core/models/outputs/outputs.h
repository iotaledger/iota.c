// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUTS_H__
#define __CORE_MODELS_OUTPUTS_H__

#include <stdint.h>

#include "core/types.h"

/**
 * @brief UTXO output types
 *
 * Extended output: Describes a deposit to a single address. The output might contain optional feature blocks and
 *                  native tokens.
 * Alias output: Describes an alias account in the ledger.
 * Foundry output: Describes a foundry that controls supply of native tokens.
 * NFT output: Describes a unique, non-fungible token deposit to a single address.
 *
 */
typedef enum {
  OUTPUT_EXTENDED = 0,  ///< Extended output
  OUTPUT_ALIAS,         ///< Alias output
  OUTPUT_FOUNDRY,       ///< Foundry output
  OUTPUT_NFT            ///< NFT output
} utxo_output_type_t;

/**
 * @brief An utxo output
 *
 */
typedef struct {
  utxo_output_type_t output_type;  ///< 0: Extended output, 1: Alias output, 2: Foundry output, 3: NFT output
  void *output;                    //< Pointer to an output
} utxo_output_t;

/**
 * @brief A list of utxo outputs
 *
 */
typedef struct utxo_outputs_list {
  utxo_output_t *output;           //< Points to a current output
  struct utxo_outputs_list *next;  //< Points to a next output
} utxo_outputs_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize an utxo output list
 *
 * @return utxo_outputs_list_t* or NULL on failure
 */
utxo_outputs_list_t *utxo_outputs_new();

/**
 * @brief Free an utxo output list
 *
 * @param[in] outputs A list of utxo outputs
 */
void utxo_outputs_free(utxo_outputs_list_t *outputs);

/**
 * @brief Add an output to an utxo output table
 *
 * @param[in] outputs A list of utxo outputs
 * @param[in] type UTXO output type
 * @param[in] output Pointer to an output
 * @return int 0 on success, -1 on failure
 */
int utxo_outputs_add(utxo_outputs_list_t **outputs, utxo_output_type_t type, void *output);

/**
 * @brief Get number of elements in an utxo output list
 *
 * @param[in] outputs A list of utxo outputs
 * @return uint16_t A number of elements
 */
uint16_t utxo_outputs_count(utxo_outputs_list_t *outputs);

/**
 * @brief Get an output pointer in the list from a given index
 *
 * @param[in] outputs A list of utxo outputs
 * @param[in] index A index of an output
 * @return utxo_output_t* A pointer to an output
 */
utxo_output_t *utxo_outputs_get(utxo_outputs_list_t *outputs, uint16_t index);

/**
 * @brief Get a length of a serialized utxo output list
 *
 * @param[in] outputs A list of utxo outputs
 * @return size_t The number of bytes of a serialized data
 */
size_t utxo_outputs_serialize_len(utxo_outputs_list_t *outputs);

/**
 * @brief Serialize utxo output list to a binary data
 *
 * @param[in] outputs A list of utxo outputs
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t utxo_outputs_serialize(utxo_outputs_list_t *outputs, byte_t buf[], size_t buf_len);

/**
 * @brief Print an utxo output list
 *
 * @param[in] outputs A list of utxo outputs
 */
void utxo_outputs_print(utxo_outputs_list_t *outputs);

#ifdef __cplusplus
}
#endif

#endif
