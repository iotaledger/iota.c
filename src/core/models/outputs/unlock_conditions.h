// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_UNLOCK_COND_H__
#define __CORE_MODELS_OUTPUT_UNLOCK_COND_H__

#include "core/address.h"

/**
 * New output features that introduce unlocking conditions, that is, they define constraints on how the output can be
 * unlocked and spent, are grouped under the field Unlock Conditions.
 *
 * Each output must not contain more than one unlock condition of each type and not all unlock condition types are
 * supported for each output type.
 *
 */

/**
 * @brief all Unlock Condition types
 *
 */
typedef enum {
  UNLOCK_COND_ADDRESS = 0,  // Address Unlock, it unlocks Ed25519 address
  UNLOCK_COND_STORAGE,      // Storage Deposit Return Unlock, to achieve conditional sending
  UNLOCK_COND_TIMELOCK,     // Timelock Unlock, an output contains a Timelock Unlock Condition can not be unlocked
                            // before the specified timelock has expired.
  UNLOCK_COND_EXPIRATION,   // Expiration Unlock, for the sender to reclaim an output after a given expiration time
                            // has been passed.
  UNLOCK_COND_STATE,        // State Controller Address Unlock, it unlocks State Controller Address of an Alias output.
  UNLOCK_COND_GOVERNOR,     // Governor Address Unlock, it unlocks Governor address of an Alias output.
  UNLOCK_COND_IMMUT_ALIAS   // Immutable Alias Address Unlock, defined for chain constrained UTXOs that can only be
                            // unlocked by a permanent Alias Address.
} unlock_cond_type_e;

/**
 * @brief An unlock condition object
 *
 */
typedef struct {
  unlock_cond_type_e type;  ///< the type of unlock condition
  void* obj;                ///< one of unlock conditions
} unlock_cond_t;

/**
 * @brief Storage Deposit Return Unlock Condition
 *
 * Defines the amount of IOTAs used as storage deposit that have to be returned to Sender.
 *
 */
typedef struct {
  address_t* addr;  // Return Address
  uint64_t amount;  // Return Amount
} unlock_cond_storage_t;

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
 * @brief A list of unlock conditions
 *
 */
typedef struct condition_list {
  unlock_cond_t* current;       // point to the current unlock condition
  struct condition_list* next;  // point to the next unlock condition
} unlock_cond_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create an Address Unlock Condition
 *
 * The Address that owns this output, that is, it can unlock it with the proper Unlock Block in a transaction.
 *
 * @param[in] addr An address object
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_addr_new(address_t const* const addr);

/**
 * @brief Create a Storage Deposit Return Unlock Condition
 *
 * The amount of IOTAs used as storage deposit that have to be returned to Sender.
 *
 * @param[in] addr A return address
 * @param[in] amount The return amount
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_storage_new(address_t const* const addr, uint64_t amount);

/**
 * @brief Create a Timelock Unlock Condition
 *
 * A milestone index and/or unix timestamp until which the output can not be unlocked.
 *
 * @param[in] milestone A milestone index
 * @param[in] time An Unix timestamp in seconds
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_timelock_new(uint32_t milestone, uint32_t time);

/**
 * @brief Create a Expiration Unlock Condition
 *
 * A milestone index and/or unix time until which only Address, defined in Address Unlock Condition, is allowed to
 * unlock the output. After the milestone index and/or unix time, only Return Address can unlock it.
 *
 * @param[in] addr A return address
 * @param[in] milestone A milestone index
 * @param[in] time An Unix timestamp in seconds
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_expir_new(address_t const* const addr, uint32_t milestone, uint32_t time);

/**
 * @brief Create a State Controll Address Unlock Condition
 *
 * @param[in] addr The state controll address
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_state_new(address_t const* const addr);

/**
 * @brief Create a Governor Address Unlock Condition
 *
 * @param[in] addr The governor address
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_governor_new(address_t const* const addr);

/**
 * @brief Create an Immutable Aliass Address Unlock Condition
 *
 * The Address that owns this output, that is, it can unlock it with the proper Unlock Block in a transaction.
 *
 * @param[in] addr An alias address object
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_immut_alias_new(address_t const* const addr);

/**
 * @brief Get the serialize bytes of the unlock condition
 *
 * @param[in] cond An unlock condition
 * @return size_t
 */
size_t condition_serialize_len(unlock_cond_t const* const cond);

/**
 * @brief Serialize an unlock condition object
 *
 * @param[in] cond An unlock condition
 * @param[in] buf A buffer holds serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t condition_serialize(unlock_cond_t* cond, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize an unlock condition object
 *
 * @param[in] buf A buffer holds unlock condition data
 * @param[in] buf_len The length of the buffer
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone an unlock condition, it should be freed after use.
 *
 * @param[in] cond An unlock condition
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_clone(unlock_cond_t* cond);

/**
 * @brief Free an unlock condition object
 *
 * @param[in] cond An unlock condition
 */
void condition_free(unlock_cond_t* cond);

/**
 * @brief Print out an unlock condition
 *
 * @param[in] cond An unlock condition
 */
void condition_print(unlock_cond_t* cond);

/**
 * @brief New an unlock condition list
 *
 * @return unlock_cond_list_t*
 */
unlock_cond_list_t* condition_list_new();

/**
 * @brief Add an unlock condition to the list
 *
 * @param[in] list An unlock condition list
 * @param[in] cond A unlock condition
 * @return int 0 on success
 */
int condition_list_add(unlock_cond_list_t** list, unlock_cond_t* cond);

/**
 * @brief Get the element count of the unlock conditions
 *
 * @param[in] list An unlock condition list object
 * @return uint8_t
 */
uint8_t condition_list_len(unlock_cond_list_t* list);

/**
 * @brief Get an unlock condition pointer from a given index
 *
 * @param[in] list An unlock condition list
 * @param[in] index The index of a unlock condition
 * @return unlock_cond_t* A pointer of the unlock condition
 */
unlock_cond_t* condition_list_get(unlock_cond_list_t* list, uint8_t index);

/**
 * @brief Get an unlock condition from a given type
 *
 * @param[in] list An unlock condition list
 * @param[in] type The type of the unlock condition
 * @return unlock_cond_t*
 */
unlock_cond_t* condition_list_get_type(unlock_cond_list_t* list, unlock_cond_type_e type);

/**
 * @brief Sort list in ascending order based on the unlock condition type
 *
 * @param[in] list An unlock condition list
 */
void condition_list_sort(unlock_cond_list_t** list);

/**
 * @brief Sort and syntactic check with the given unlock condition list
 *
 * @param[in] list An unlock condition list
 * @return int 0 on success
 */
int condition_list_syntactic(unlock_cond_list_t** list);

/**
 * @brief Get serialized bytes of the unlock condition list
 *
 * @param[in] list An unlock condition list
 * @return size_t
 */
size_t condition_list_serialize_len(unlock_cond_list_t* list);

/**
 * @brief Serialize an unlock condition list
 *
 * @param[in] list An unlock condition list
 * @param[in] buf A buffer holds serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t
 */
size_t condition_list_serialize(unlock_cond_list_t** list, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize an unlock condition list
 *
 * @param[in] buf A buffer holds serialized unlock condition list
 * @param[in] buf_len The length of the buffer
 * @return unlock_cond_list_t*
 */
unlock_cond_list_t* condition_list_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Free an unlock condition list
 *
 * @param[in] list An unlock condition list
 */
void condition_list_free(unlock_cond_list_t* list);

/**
 * @brief Clone an unlock condition list
 *
 * @param[in] list An unlock condition list
 * @return unlock_cond_list_t*
 */
unlock_cond_list_t* condition_list_clone(unlock_cond_list_t const* const list);

/**
 * @brief Print out the unlock condition list
 *
 * @param[in] list An unlock condition list
 * @param[in] indent Tab indentation when printing the list
 */
void condition_list_print(unlock_cond_list_t* list, uint8_t indent);

#ifdef __cplusplus
}
#endif

#endif
