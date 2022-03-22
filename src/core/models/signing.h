// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_SIGNING_H__
#define __CORE_MODELS_SIGNING_H__

#include <inttypes.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/unlock_block.h"

/**
 * @brief A signing data structure. This data is needed when unlock blocks are creating and transaction gets signed.
 *
 */
typedef struct {
  address_t unlock_address;  ///< Address in Unlock Condition (Address, Governor, State Controller) - ED25519/NFT/Alias
  byte_t hash[CRYPTO_BLAKE2B_160_HASH_BYTES];  ///< Optional, a NFT/Alias ID in the utxo_output
  ed25519_keypair_t* keypair;                  ///< Optional, ed25519 keypair (this is for ed25519 address)
} signing_data_t;

/**
 * @brief A list of signing data.
 *
 * This list needs to have the same order of signing data for unspent outputs as in utxo_inputs_list_t.
 *
 */
typedef struct signing_data_list {
  signing_data_t* sign_data;       //< Points to a current signing data
  struct signing_data_list* next;  //< Points to a next signing data list
} signing_data_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize a signing data list
 *
 * @return signing_data_list_t* or NULL pointer
 */
signing_data_list_t* signing_new();

/**
 * @brief Free a signing data list
 *
 * @param[in] signing_data_list Signing data list
 */
void signing_free(signing_data_list_t* signing_data_list);

/**
 * @brief Find a signing data by a given index
 *
 * @param[in] unlock_address Address Unlock Condition Address - ED25519/NFT/Alias
 * @param[in] hash Optional, a NFT/Alias ID in the utxo_output
 * @param[in] hash_len A length of hash array, 0 if hash is NULL
 * @param[in] keypair TOptional, ed25519 keypair of this input (this is for ed25519 address)
 * @param[out] sign_data_list Signing data list which will be populated by a new element
 * @return int 0 on success
 */
int signing_data_add(address_t* unlock_address, byte_t hash[], uint8_t hash_len, ed25519_keypair_t* keypair,
                     signing_data_list_t** sign_data_list);

/**
 * @brief Get number of elements in a signing data list
 *
 * @param[in] signing_data_list Signing data list
 * @return uint8_t Number of elements
 */
uint8_t signing_data_count(signing_data_list_t* signing_data_list);

/**
 * @brief Find a signing data by a given index
 *
 * @param[in] signing_data_list Signing data list
 * @param[in] index An index in the list
 * @return signing_data_t* or NULL pointer
 */
signing_data_t* signing_get_data_by_index(signing_data_list_t* signing_data_list, uint8_t index);

/**
 * @brief Create unlock blocks and sign transaction
 *
 * @param[in] essence_hash An essence hash
 * @param[in] essence_hash_len Length of an essence hash array
 * @param[in] inputs An UTXO input list
 * @param[in] sign_data_list Signing data list
 * @param[out] unlock_blocks A list of unlock blocks which will be created
 * @return int 0 on success
 */
int signing_transaction_sign(byte_t essence_hash[], uint8_t essence_hash_len, utxo_inputs_list_t* inputs,
                             signing_data_list_t* sign_data_list, unlock_list_t** unlock_blocks);

#ifdef __cplusplus
}
#endif

#endif  // __CORE_MODELS_SIGNING_H__
