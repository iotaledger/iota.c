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
  MSG_UNSIGNED_TX = 0,
  MSG_MILESTONE,
  MSG_INDEXATION,
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

#ifdef __cplusplus
}
#endif

#endif
