// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_V1_GET_MSG_H__
#define __CLIENT_API_V1_GET_MSG_H__

#include <stdbool.h>
#include <stdint.h>

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

res_message_t *res_message_new();

void res_message_free(res_message_t *msg);

// get msg data by message id
int get_message_by_id(iota_client_conf_t const *conf, char const msg_id[], res_message_t *res);

int deser_get_message(char const *const j_str, res_message_t *res);

#ifdef __cplusplus
}
#endif

#endif
