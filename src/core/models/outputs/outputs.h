// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUTS_H__
#define __CORE_MODELS_OUTPUTS_H__

#include <stdint.h>

#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/output_nft.h"
#include "core/types.h"

#define UTXO_OUTPUT_MAX_COUNT 127

static const uint64_t MAX_IOTA_SUPPLY = 2779530283277761;

/**
 * @brief UTXO output types
 *
 * SigLockedSingleOutput: Defines an output (with a certain amount) to a single target address which is unlocked via
 *                        a signature proving ownership over the given address.
 * SigLockedDustAllowanceOutput: Works in the same way as a SigLockedSingleOutput but additionally controls the dust
 *                               allowance on the target address.
 * Treasury output: Describes an output which holds the treasury of a network.
 * Basic output: Describes a deposit to a single address. The output might contain optional feature blocks and
 *                  native tokens.
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
 * @brief An utxo output
 *
 */
typedef struct {
  utxo_output_type_t output_type;  ///< 3: Basic output, 4: Alias output, 5: Foundry output, 6: NFT output
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
 * @return utxo_outputs_list_t* a NULL pointer
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
 * @brief Deserialize binary data to a utxo output list object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return utxo_outputs_list_t* The deserialized utxo output list, NULL on errors
 */
utxo_outputs_list_t *utxo_outputs_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Print an utxo output list
 *
 * @param[in] outputs A list of utxo outputs
 * @param[in] indentation Tab indentation when printing utxo output list
 */
void utxo_outputs_print(utxo_outputs_list_t *outputs, uint8_t indentation);

#ifdef __cplusplus
}
#endif

#endif
