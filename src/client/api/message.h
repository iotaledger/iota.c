// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_MESSAGE_H__
#define __CLIENT_API_MESSAGE_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/types.h"
#include "core/utils/byte_buffer.h"
#include "utarray.h"

#define API_MSG_ID_HEX_STR_LEN (64 + 1)
#define API_TX_ID_HEX_STR_LEN (64 + 1)
#define API_ADDR_HEX_STR_LEN (64 + 1)
#define API_PUB_KEY_HEX_STR_LEN (64 + 1)
#define API_SIGNATURE_HEX_STR_LEN (128 + 1)
#define API_SIGNATURE_BLOCK_STR_LEN (1 + API_PUB_KEY_HEX_STR_LEN + API_SIGNATURE_HEX_STR_LEN)

typedef enum {
  MSG_PAYLOAD_TRANSACTION = 0,
  MSG_PAYLOAD_MILESTONE,
  MSG_PAYLOAD_INDEXATION,
  MSG_PAYLOAD_UNKNOW = -1,
} msg_payload_type_t;

// TODO update mileestone structure: https://github.com/iotaledger/protocol-rfcs/pull/19
typedef struct {
  uint64_t timestamp;
  uint32_t index;
  char inclusion_merkle_proof[64 + 1];  // hex string with 64 length
  UT_array *signatures;
} payload_milestone_t;

typedef struct {
  byte_buf_t *index;
  byte_buf_t *data;
} payload_index_t;

typedef struct {
  uint32_t tx_output_index;
  char tx_id[API_TX_ID_HEX_STR_LEN];
} payload_tx_input_t;

typedef struct {
  uint64_t amount;
  char address[API_ADDR_HEX_STR_LEN];
} payload_tx_output_t;

/**
 * @brief An unlocked block in strings
 *
 */
typedef struct {
  uint8_t block_type;  ///< 0 denotes a Signature Unlock Block, 1 denotes a Reference Unlock Block.
  uint16_t reference;  ///< Represents the index of a pervious unlock block
  char *sig_block;     ///< ed25519 public key + signature in hex string
} payload_unlock_block_t;

typedef UT_array api_utxo_inputs_t;
typedef UT_array api_utxo_outputs_t;
typedef UT_array api_unlock_blocks_t;

typedef struct {
  api_utxo_inputs_t *inputs;
  api_utxo_outputs_t *outputs;
  api_unlock_blocks_t *unlock_blocks;
  payload_t type;
  void *payload;
} payload_tx_t;

/**
 * @brief A message object
 *
 */
typedef struct {
  char net_id[32];           ///< string of network ID hash
  char nonce[32];            ///< string of nonce
  UT_array *parent_msg_ids;  ///< a list of parent IDs
  payload_t type;            ///< payload type
  void *payload;             ///< NULL if no payload
} message_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a transaction payload object
 *
 * @return payload_tx_t*
 */
payload_tx_t *payload_tx_new();

/**
 * @brief Free a transaction payload object
 *
 * @param[in] tx A transaction payload
 */
void payload_tx_free(payload_tx_t *tx);

/**
 * @brief Allocate a milestone payload object
 *
 * @return payload_milestone_t*
 */
payload_milestone_t *payload_milestone_new();

/**
 * @brief Free a milestone payload object
 *
 * @param[in] ms A milestone object
 */
void payload_milestone_free(payload_milestone_t *ms);

/**
 * @brief Allocate an indexcation payload object
 *
 * @return payload_index_t*
 */
payload_index_t *payload_index_new();

/**
 * @brief Free an indexcation payload object
 *
 * @param[in] idx An indexcation payload
 */
void payload_index_free(payload_index_t *idx);

/**
 * @brief Allocate a message object
 *
 * @return message_t*
 */
message_t *api_message_new();

/**
 * @brief Free a message object
 *
 * @param[in] msg A message object
 */
void api_message_free(message_t *msg);

/**
 * @brief Gets the number of parent IDs
 *
 * @param[in] msg A message object
 * @return size_t
 */
size_t api_message_parent_count(message_t *msg);

/**
 * @brief Gets a parent ID by a given index
 *
 * @param[in] msg A message object
 * @param[in] index A index of a message ID
 * @return char*
 */
char *api_message_parent_id(message_t *msg, size_t index);

/**
 * @brief Adds a reference message id to the message
 *
 * @param[in] msg A message object
 * @param[in] msg_id A message id string
 */
void api_message_add_parent(message_t *msg, char const msg_id[]);

/**
 * @brief Get inputs count from transaction payload
 *
 * @param[in] tx A transaction payload object
 * @return size_t
 */
size_t payload_tx_inputs_count(payload_tx_t const *const tx);

/**
 * @brief Get the transaction ID from transaction payload
 *
 * @param[in] tx A transaction payload object
 * @param[in] index The index of input element
 * @return char*
 */
char *payload_tx_inputs_tx_id(payload_tx_t const *const tx, size_t index);

/**
 * @brief Get output index from transaction payload
 *
 * @param[in] tx A transaction payload object
 * @param[in] index The index of input element
 * @return uint32_t
 */
uint32_t payload_tx_inputs_tx_output_index(payload_tx_t const *const tx, size_t index);

/**
 * @brief Get outputs count
 *
 * @param[in] tx A transaction payload object
 * @return size_t
 */
size_t payload_tx_outputs_count(payload_tx_t const *const tx);

/**
 * @brief Get address from outputs
 *
 * @param[in] tx A transaction payload object
 * @param[in] index The index of the output
 * @return char*
 */
char *payload_tx_outputs_address(payload_tx_t const *const tx, size_t index);

/**
 * @brief Get amount from outputs
 *
 * @param[in] tx A transaction payload object
 * @param[in] index The index of the output
 * @return uint64_t
 */
uint64_t payload_tx_outputs_amount(payload_tx_t const *const tx, size_t index);

/**
 * @brief Get unlocked block size
 *
 * @param[in] tx A transaction payload object
 * @return size_t
 */
size_t payload_tx_blocks_count(payload_tx_t const *const tx);

/**
 * @brief Get public key from unlocked block
 *
 * @param[in] tx A transaction payload object
 * @param[in] index The index of unlocked block
 * @return char*
 */
char *payload_tx_blocks_public_key(payload_tx_t const *const tx, size_t index);

/**
 * @brief Get signature from unlocked block
 *
 * @param[in] tx A transaction payload object
 * @param[in] index The index of unlocked block
 * @return char*
 */
char *payload_tx_blocks_signature(payload_tx_t const *const tx, size_t index);

/**
 * @brief Add a signature block into the unlock blocks
 *
 * @param[in] tx A transaction payload object
 * @param[in] sig A string of signature block
 * @param[in] sig_len The length of signature block
 * @return int 0 on success
 */
int payload_tx_add_sig_block(payload_tx_t const *const tx, char const sig[], size_t sig_len);

/**
 * @brief Add a reference into the unlock blocks
 *
 * @param[in] tx A transaction payload object
 * @param[in] ref The index of reference
 * @return int 0 on success
 */
int payload_tx_add_ref_block(payload_tx_t const *const tx, uint16_t ref);

/**
 * @brief Get the reference by a given index of the unlock block
 *
 * @param[in] tx A transaction payload object
 * @param[in] index The index of unlock block
 * @return uint16_t 65536(UINT16_MAX) on fails
 */
uint16_t payload_tx_blocks_reference(payload_tx_t const *const tx, size_t index);

#ifdef __cplusplus
}
#endif

#endif