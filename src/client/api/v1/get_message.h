// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_GET_MSG_H__
#define __CLIENT_API_V1_GET_MSG_H__

#include <stdbool.h>
#include <stdint.h>

#include "utarray.h"

#include "client/api/v1/response_error.h"
#include "client/client_service.h"
#include "core/types.h"
#include "core/utils/byte_buffer.h"

typedef enum {
  MSG_PAYLOAD_TRANSACTION = 0,
  MSG_PAYLOAD_MILESTONE,
  MSG_PAYLOAD_INDEXATION,
  MSG_PAYLOAD_UNKNOW = -1,
} msg_payload_type_t;

typedef struct {
  uint64_t timestamp;
  uint32_t index;
  char inclusion_merkle_proof[128];  // hex string with 128 length
  UT_array *signatures;
} payload_milestone_t;

typedef struct {
  byte_buf_t *index;
  byte_buf_t *data;
} payload_index_t;

typedef struct {
  uint32_t tx_output_index;
  char tx_id[64];
} payload_tx_input_t;

typedef struct {
  uint64_t amount;
  char address[64];
} payload_tx_output_t;

typedef struct {
  char pub_key[64];
  char signature[128];
} payload_unlock_block_t;

typedef UT_array utxo_inputs_t;
typedef UT_array utxo_outputs_t;
typedef UT_array unlock_blocks_t;

typedef struct {
  utxo_inputs_t *intputs;
  utxo_outputs_t *outputs;
  unlock_blocks_t *unlock_blocks;
  void *payload;
} payload_tx_t;

typedef struct {
  char net_id[32];  // string of uint64_t
  char parent1[64];
  char parent2[64];
  char nonce[32];  // string of uint64_t
  payload_t type;
  void *payload;
} get_message_t;

typedef struct {
  bool is_error;
  union {
    res_err_t *error;
    get_message_t *msg;
  } u;
} res_message_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate a message for API response
 *
 * @return res_message_t*
 */
res_message_t *res_message_new();

/**
 * @brief Free a message object
 *
 * @param[in] msg A message object
 */
void res_message_free(res_message_t *msg);

/**
 * @brief Get the message data from a given message ID
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] msg_id A message ID to query
 * @param[out] res The message body of the given ID
 * @return int 0 on success
 */
int get_message_by_id(iota_client_conf_t const *conf, char const msg_id[], res_message_t *res);

/**
 * @brief The message response deserialization
 *
 * @param[in] j_str A string of json object
 * @param[out] res the message object
 * @return int 0 on success
 */
int deser_get_message(char const *const j_str, res_message_t *res);

/**
 * @brief Get the signature count in message
 *
 * @param[in] res The message object
 * @return size_t
 */
size_t get_message_milestone_signature_count(res_message_t const *const res);

/**
 * @brief Extra a signature string from message
 *
 * @param[in] res The message object
 * @param[in] index The index of signature
 * @return char* NULL on failed.
 */
char *get_message_milestone_signature(res_message_t const *const res, size_t index);

/**
 * @brief Get the message payload type
 *
 * @param[in] res The message object
 * @return msg_payload_type_t
 */
msg_payload_type_t get_message_payload_type(res_message_t const *const res);

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

#ifdef __cplusplus
}
#endif

#endif
