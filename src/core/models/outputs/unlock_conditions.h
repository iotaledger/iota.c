// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_UNLOCK_COND_H__
#define __CORE_MODELS_OUTPUT_UNLOCK_COND_H__

#include "core/address.h"
#include "core/types.h"

/**
 * New output features that introduce unlocking conditions, that is, they define constraints on how the output can be
 * unlocked and spent, are grouped under the field Unlock Conditions.
 * Each output must not contain more than one unlock condition of each type and not all unlock condition types are
 * supported for each output type.
 *
 */

// Maximun Unlock Condition Blocks in a list
#define MAX_UNLOCK_CONDITION_BLOCK_COUNT 4

/**
 * @brief all Unlock Condition types
 *
 */
typedef enum {
  UNLOCK_COND_ADDRESS = 0,  // Address Unlock, it unlocks Ed25519 address
  UNLOCK_COND_DUST,         // Dust Deposit Return Unlock, to achieve conditional sending
  UNLOCK_COND_TIMELOCK,    // Timelock Unlock, an output contains a Timelock Unlock Condition can not be unlocked before
                           // the specified timelock has expired.
  UNLOCK_COND_EXPIRATION,  // Expiration Unlock, for the sender to reclaim an output after a given expiration time has
                           // been passed.
  UNLOCK_COND_STATE,       // State Controller Address Unlock, it unlocks State Controller Address of an Alias output.
  UNLOCK_COND_GOVERNOR     // Governor Address Unlock, it unlocks Governor address of an Alias output.
} unlock_cond_e;

/**
 * @brief An unlock condition block object
 *
 */
typedef struct {
  unlock_cond_e type;  ///< the type of unlock condition
  void* block;         ///< one of unlock conditions
} unlock_cond_blk_t;

/**
 * @brief Dust Deposit Return Unlock Condition
 *
 * Defines the amount of IOTAs used as dust deposit that have to be returned to Sender.
 *
 */
typedef struct {
  address_t* addr;  // Return Address
  uint64_t amount;  // Return Amount
} unlock_cond_dust_t;

/**
 * @brief Timelock Unlock Condition
 *
 * Defines a milestone index and/or unix timestamp until which the output can not be unlocked.
 *
 */
typedef struct {
  uint32_t milestone;  // The milestone index starting from which the output can be consumed.
  uint32_t time;       // Unix time (seconds since Unix epoch) starting from which the output can be consumed.
} unlock_cond_timelock_t;

/**
 * @brief Expiration Unlock Condition
 *
 * Defines a milestone index and/or unix time until which only Address, defined in Address Unlock Condition, is allowed
 * to unlock the output. After the milestone index and/or unix time, only Return Address can unlock it.
 *
 */
typedef struct {
  address_t* addr;     // Return Address
  uint32_t milestone;  // Before this milestone index, Address Unlock Condition is allowed to unlock the output, after
                       // that only the address defined in Return Address.
  uint32_t time;  // Before this unix time, Address Unlock Condition is allowed to unlock the output, after that only
                  // the address defined in Return Address.
} unlock_cond_expir_t;

/**
 * @brief A list of unlock condition blocks
 *
 */
typedef struct cond_blk_list {
  unlock_cond_blk_t* blk;      // point to the current condition block
  struct cond_blk_list* next;  // point to the next condition block
} cond_blk_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a Address Unlock Condition block
 *
 * The Address that owns this output, that is, it can unlock it with the proper Unlock Block in a transaction.
 *
 * @param[in] addr An address object
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* new_cond_blk_addr(address_t const* const addr);

/**
 * @brief Create a Dust Deposit Return Unlock Condition block
 *
 * The amount of IOTAs used as dust deposit that have to be returned to Sender.
 *
 * @param[in] addr A return address
 * @param[in] amount The return amount
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* new_cond_blk_dust(address_t const* const addr, uint64_t amount);

/**
 * @brief Create a Timelock Unlock Condition block
 *
 * A milestone index and/or unix timestamp until which the output can not be unlocked.
 *
 * @param[in] milestone A milestone index
 * @param[in] time An Unix timestamp in seconds
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* new_cond_blk_timelock(uint32_t milestone, uint32_t time);

/**
 * @brief Create a Expiration Unlock Condition block
 *
 * A milestone index and/or unix time until which only Address, defined in Address Unlock Condition, is allowed to
 * unlock the output. After the milestone index and/or unix time, only Return Address can unlock it.
 *
 * @param[in] addr A return address
 * @param[in] milestone A milestone index
 * @param[in] time An Unix timestamp in seconds
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* new_cond_blk_expir(address_t const* const addr, uint32_t milestone, uint32_t time);

/**
 * @brief Create a State Controll Address Unlock Condition block
 *
 * @param[in] addr The state controll address
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* new_cond_blk_state(address_t const* const addr);

/**
 * @brief Create a Governor Address Unlock Condition
 *
 * @param[in] addr The governor address
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* new_cond_blk_governor(address_t const* const addr);

/**
 * @brief Get the serialize bytes of the block
 *
 * @param[in] blk An unlock condition block
 * @return size_t
 */
size_t cond_blk_serialize_len(unlock_cond_blk_t const* const blk);

/**
 * @brief Serialize an unlock condition block object
 *
 * @param[in] blk An unlock condition block
 * @param[in] buf A buffer holds serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t cond_blk_serialize(unlock_cond_blk_t* blk, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize an unlock condition block object
 *
 * @param[in] buf A buffer holds unlock condition data
 * @param[in] buf_len The length of the buffer
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* cond_blk_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone an unlock condition, it should be freed after use.
 *
 * @param[in] blk An unlock condition
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* cond_blk_clone(unlock_cond_blk_t* blk);

/**
 * @brief Free an unlock condition block object
 *
 * @param[in] blk An unlock condition
 */
void free_cond_blk(unlock_cond_blk_t* blk);

/**
 * @brief Print out an unlock condition block
 *
 * @param[in] blk An unlock condition
 */
void cond_blk_print(unlock_cond_blk_t* blk);

/**
 * @brief New an unlock condition block list
 *
 * @return cond_blk_list_t*
 */
cond_blk_list_t* new_cond_blk_list();

/**
 * @brief Add an unlock condition to the list
 *
 * @param[in] list An unlock condition list
 * @param[in] blk A unlock condition block
 * @return int 0 on success
 */
int cond_blk_list_add(cond_blk_list_t** list, unlock_cond_blk_t* blk);

/**
 * @brief Get the element count of the condition blocks
 *
 * @param[in] list An unlock condition list object
 * @return uint8_t
 */
uint8_t cond_blk_list_len(cond_blk_list_t* list);

/**
 * @brief Get an unlock condition block pointer from a given index
 *
 * @param[in] list An unlock condition list
 * @param[in] index The index of a condition block
 * @return feat_block_t* A pointer of the condition block
 */
unlock_cond_blk_t* cond_blk_list_get(cond_blk_list_t* list, uint8_t index);

/**
 * @brief Get an unlock condition from a given type
 *
 * @param[in] list An unlock condition list
 * @param[in] type The type of the unlock condition
 * @return unlock_cond_blk_t*
 */
unlock_cond_blk_t* cond_blk_list_get_type(cond_blk_list_t* list, unlock_cond_e type);

/**
 * @brief Sort list in ascending order based on the block type
 *
 * @param[in] list An unlock condition list
 */
void cond_blk_list_sort(cond_blk_list_t** list);

/**
 * @brief Sort and syntactic check with the given unlock condition list
 *
 * @param[in] list An unlock condition list
 * @return int 0 on success
 */
int cond_blk_list_syntactic(cond_blk_list_t** list);

/**
 * @brief Get serialized bytes of the unlock condition list
 *
 * @param[in] list An unlock condition list
 * @return size_t
 */
size_t cond_blk_list_serialize_len(cond_blk_list_t* list);

/**
 * @brief Serialize an unlock condition list
 *
 * @param[in] list An unlock condition list
 * @param[in] buf A buffer holds serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t
 */
size_t cond_blk_list_serialize(cond_blk_list_t** list, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize an unlock condition list
 *
 * @param[in] buf A buffer holds serialized unlock condition list
 * @param[in] buf_len The length of the buffer
 * @return cond_blk_list_t*
 */
cond_blk_list_t* cond_blk_list_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Free an unlock condition list
 *
 * @param[in] list An unlock condition list
 */
void free_cond_blk_list(cond_blk_list_t* list);

/**
 * @brief Clone an unlock condition list
 *
 * @param[in] list An unlock condition list
 * @return cond_blk_list_t*
 */
cond_blk_list_t* cond_blk_list_clone(cond_blk_list_t const* const list);

/**
 * @brief Print out the unlock condition list
 *
 * @param[in] list An unlock condition list
 * @param[in] indent Tab indentation when printing the list
 */
void cond_blk_list_print(cond_blk_list_t* list, uint8_t indent);

#ifdef __cplusplus
}
#endif

#endif
