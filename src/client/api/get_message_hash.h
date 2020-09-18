#ifndef __CLIENT_API_GET_MSG_HASH_H__
#define __CLIENT_API_GET_MSG_HASH_H__

#include <stdbool.h>

#include "client/api/response_error.h"
#include "core/models/message.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  bool is_error;
  union {
    res_err_t* error;
    message_t* msg;
  } msg_u;
} res_msg_t;

res_msg_t* res_msg_new();

void res_msg_free(res_msg_t* msg);

int deser_message_payload(char const* const j_str, res_msg_t* msg);

#ifdef __cplusplus
}
#endif

#endif