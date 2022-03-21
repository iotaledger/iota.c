// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_SIGNING_H__
#define __CORE_MODELS_SIGNING_H__

#include <inttypes.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/unlock_block.h"

typedef struct {
  address_t unlock_address;        ///< Address Unlock Condition Address - ED25519/NFT/Alias
  address_t* utxo_output_address;  ///< Optional, Address that will be created from the NFT/Alias ID in the utxo_output
  ed25519_keypair_t* keypair;      ///< Optional, ed25519 keypair of this input (this is for ed25519 address)
} signing_data_t;

typedef struct signing_data_list {
  signing_data_t* sign_data;       //< Points to a current signing data
  struct signing_data_list* next;  //< Points to a next signing data list
} signing_data_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize a transaction signing data list
 *
 * @return signing_data_list_t* or NULL pointer
 */
signing_data_list_t* signing_transaction_new();

/**
 * @brief Free a transaction signing data list
 *
 * @param[in] signing_data_list Transaction signing data list
 */
void signing_transaction_free(signing_data_list_t* signing_data_list);

/**
 * @brief Find a transaction signing data by a given index
 *
 * @param[in] unlock_address Address Unlock Condition Address - ED25519/NFT/Alias
 * @param[in] utxo_output_address Optional, Address that will be created from the NFT/Alias ID in the utxo_output
 * @param[in] keypair TOptional, ed25519 keypair of this input (this is for ed25519 address)
 * @param[out] sign_data_list Transaction signing data list which will be populated by a new element
 * @return int 0 on success
 */
int signing_transaction_data_add(address_t* unlock_address, address_t* utxo_output_address, ed25519_keypair_t* keypair,
                                 signing_data_list_t** sign_data_list);

/**
 * @brief Get number of elements in a transaction signing data list
 *
 * @param[in] signing_data_list Transaction signing data list
 * @return uint8_t Number of elements
 */
uint8_t signing_transaction_data_count(signing_data_list_t* signing_data_list);

/**
 * @brief Find a transaction signing data by a given index
 *
 * @param[in] signing_data_list Transaction signing data list
 * @param[in] index An index in the list
 * @return signing_data_t* or NULL pointer
 */
signing_data_t* signing_transaction_data_get_by_index(signing_data_list_t* signing_data_list, uint8_t index);

/**
 * @brief Sign transaction message
 *
 * @param[in] essence_hash An essence hash
 * @param[in] inputs An UTXO input list
 * @param[in] sign_data_list Transaction signing data list
 * @param[out] unlock_blocks A list of unlock blocks which will be created
 * @return int 0 on success
 */
int signing_transaction_sign(byte_t essence_hash[], utxo_inputs_list_t* inputs, signing_data_list_t* sign_data_list,
                             unlock_list_t** unlock_blocks);

#ifdef __cplusplus
}
#endif

#endif  // __CORE_MODELS_SIGNING_H__
