// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUTS_H__
#define __CORE_MODELS_OUTPUTS_H__

#include <stdint.h>

#include "core/models/outputs/byte_cost_config.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/output_nft.h"

/**
 * @brief UTXO output types
 *
 * SigLockedSingleOutput: Defines an output (with a certain amount) to a single target address which is unlocked via
 *                        a signature proving ownership over the given address.
 * SigLockedDustAllowanceOutput: Works in the same way as a SigLockedSingleOutput but additionally controls the dust
 *                               allowance on the target address.
 * Treasury output: Describes an output which holds the treasury of a network.
 * Basic output: Describes a deposit to a single address. The output might contain optional features and native tokens.
 * Alias output: Describes an alias account in the ledger.
 * Foundry output: Describes a foundry that controls supply of native tokens.
 * NFT output: Describes a unique, non-fungible token deposit to a single address.
 *
 */
typedef enum {
  OUTPUT_SINGLE_OUTPUT = 0,   ///< SigLockedSingleOutput, deprecated
  OUTPUT_DUST_ALLOWANCE = 1,  ///< SigLockedDustAllowanceOutput, deprecated
  OUTPUT_TREASURY = 2,        ///< Treasury output, not supported in this library
  OUTPUT_BASIC = 3,           ///< Basic output
  OUTPUT_ALIAS = 4,           ///< Alias output
  OUTPUT_FOUNDRY = 5,         ///< Foundry output
  OUTPUT_NFT = 6              ///< NFT output
} utxo_output_type_t;

/**
 * @brief An UTXO output
 *
 */
typedef struct {
  utxo_output_type_t output_type;  ///< 3: Basic output, 4: Alias output, 5: Foundry output, 6: NFT output
  void *output;                    //< Pointer to an output
} utxo_output_t;

/**
 * @brief A list of UTXO outputs
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
 * @brief Initialize an UTXO output list
 *
 * @return A NULL pointer
 */
utxo_outputs_list_t *utxo_outputs_new();

/**
 * @brief Free an UTXO output list
 *
 * @param[in] outputs A list of UTXO outputs
 */
void utxo_outputs_free(utxo_outputs_list_t *outputs);

/**
 * @brief Add an output to an UTXO output table
 *
 * @param[in] outputs A list of UTXO outputs
 * @param[in] type An UTXO output type
 * @param[in] output A pointer to an output
 * @return int 0 on success, -1 on failure
 */
int utxo_outputs_add(utxo_outputs_list_t **outputs, utxo_output_type_t type, void *output);

/**
 * @brief Get number of elements in an UTXO output list
 *
 * @param[in] outputs A list of UTXO outputs
 * @return uint16_t A number of elements
 */
uint16_t utxo_outputs_count(utxo_outputs_list_t *outputs);

/**
 * @brief Get an output pointer in the list from a given index
 *
 * @param[in] outputs A list of UTXO outputs
 * @param[in] index An index of an output
 * @return utxo_output_t* A pointer to an output
 */
utxo_output_t *utxo_outputs_get(utxo_outputs_list_t *outputs, uint16_t index);

/**
 * @brief Get a length of a serialized UTXO output list
 *
 * @param[in] outputs A list of UTXO outputs
 * @return size_t The number of bytes of a serialized data
 */
size_t utxo_outputs_serialize_len(utxo_outputs_list_t *outputs);

/**
 * @brief Serialize an UTXO output list to a binary data
 *
 * @param[in] outputs A list of UTXO outputs
 * @param[out] buf A buffer holds the serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t utxo_outputs_serialize(utxo_outputs_list_t *outputs, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize binary data to an UTXO output list object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return utxo_outputs_list_t* The deserialized UTXO output list, NULL on errors
 */
utxo_outputs_list_t *utxo_outputs_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Print an UTXO output list
 *
 * @param[in] outputs A list of UTXO outputs
 * @param[in] indentation Tab indentation when printing UTXO output list
 */
void utxo_outputs_print(utxo_outputs_list_t *outputs, uint8_t indentation);

/**
 * @brief UTXO Output syntactic validation
 *
 * @param[in] outputs A list of UTXO outputs
 * @param[in] byte_cost The Byte Cost configure
 * @return true Valid
 * @return false Invalid
 */
bool utxo_outputs_syntactic(utxo_outputs_list_t *outputs, byte_cost_config_t *byte_cost);

#ifdef __cplusplus
}
#endif

#endif
