// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

// TODO remove
#include "client/api/json_parser/inputs.h"
#include "client/api/json_parser/json_utils.h"
#include "client/api/json_parser/outputs.h"
#include "client/api/json_parser/unlock_blocks.h"

#include "client/api/json_parser/json_keys.h"
#include "client/api/json_parser/json_utils.h"
#include "client/api/json_parser/message.h"
#include "client/api/restful/get_message.h"
#include "client/network/http.h"
#include "core/address.h"
#include "core/utils/iota_str.h"

static int milestone_deserialize(cJSON *milestone_obj, res_message_t *res) {
  if (milestone_obj == NULL || res == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;
  milestone_t *ms = milestone_payload_new();
  if (ms == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  // parsing index
  if ((ret = json_get_uint64(milestone_obj, JSON_KEY_INDEX, &ms->index)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_INDEX);
    goto end;
  }

  // parsing timestamp
  if ((ret = json_get_uint64(milestone_obj, JSON_KEY_TIMESTAMP, &ms->timestamp)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    goto end;
  }

  // parsing inclusion Merkle proof
  if ((ret = json_get_string(milestone_obj, JSON_KEY_INCLUSION_MKL, ms->inclusion_merkle_proof,
                             sizeof(ms->inclusion_merkle_proof))) != 0) {
    printf("[%s:%d]: parsing %s string failed\n", __func__, __LINE__, JSON_KEY_INCLUSION_MKL);
    goto end;
  }

  // parsing signatures
  if ((ret = json_string_array_to_utarray(milestone_obj, JSON_KEY_SIGNATURES, ms->signatures)) != 0) {
    printf("[%s:%d]: parsing %s array failed\n", __func__, __LINE__, JSON_KEY_SIGNATURES);
  }

end:
  if (ret != 0) {
    milestone_payload_free(ms);
    res->u.msg->payload = NULL;
  } else {
    res->u.msg->payload = (void *)ms;
  }

  return ret;
}

static int transaction_deserialize(cJSON *tx_obj, res_message_t *res) {
  if (tx_obj == NULL || res == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  transaction_payload_t *tx = tx_payload_new();
  if (tx == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  // parsing essence
  cJSON *essence_obj = cJSON_GetObjectItemCaseSensitive(tx_obj, JSON_KEY_ESSENCE);
  if (essence_obj) {
    // inputs array
    if ((ret = json_inputs_deserialize(essence_obj, &tx->essence->inputs)) != 0) {
      goto end;
    }

    // outputs array
    if ((ret = json_outputs_deserialize(essence_obj, tx->essence)) != 0) {
      goto end;
    }

    // payload
    cJSON *payload_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_PAYLOAD);
    if (!cJSON_IsNull(payload_obj)) {
      /*
      "payload": {
          "type": 2,
          "index": "45535033322057616c6c6574",
          "data": "73656e742066726f6d2065737033322076696120696f74612e6300"
      }
      */
      cJSON *payload_type = cJSON_GetObjectItemCaseSensitive(payload_obj, JSON_KEY_TYPE);
      if (cJSON_IsNumber(payload_type)) {
        if (payload_type->valueint == 2) {
#if 0  // FIXME
          indexation_t *idx = indexation_new();
          if (idx == NULL) {
            printf("[%s:%d]: allocate index payload failed\n", __func__, __LINE__);
          } else {
            if (deser_indexation(payload_obj, idx) != 0) {
              printf("[%s:%d]: parsing index payload failed\n", __func__, __LINE__);
              indexation_free(idx);
            } else {
              tx->type = CORE_MESSAGE_PAYLOAD_INDEXATION;
              tx->essence->payload = idx;
            }
          }
#endif
        } else {
          printf("[%s:%d]: payload type %d is not supported\n", __func__, __LINE__, payload_type->valueint);
        }
      } else {
        printf("[%s:%d]: payload type must be a number\n", __func__, __LINE__);
      }
    }

    // unlock blocks
    cJSON *blocks_obj = cJSON_GetObjectItemCaseSensitive(tx_obj, JSON_KEY_UNLOCK_BLOCKS);
    if (cJSON_IsArray(blocks_obj)) {
      ret = json_unlock_blocks_deserialize(blocks_obj, tx->unlock_blocks);
    } else {
      printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_UNLOCK_BLOCKS);
    }

  } else {
    printf("[%s:%d]: %s not found in the message\n", __func__, __LINE__, JSON_KEY_ESSENCE);
  }

end:
  if (ret != 0) {
    tx_payload_free(tx);
    res->u.msg->payload = NULL;
  } else {
    res->u.msg->payload = (void *)tx;
  }

  return ret;
}

res_message_t *res_message_new() {
  res_message_t *msg = malloc(sizeof(res_message_t));
  if (msg) {
    msg->is_error = false;
    msg->u.msg = NULL;
    return msg;
  }
  return NULL;
}

void res_message_free(res_message_t *msg) {
  if (msg) {
    if (msg->is_error) {
      res_err_free(msg->u.error);
    } else {
      if (msg->u.msg) {
        core_message_free(msg->u.msg);
      }
    }
    free(msg);
  }
}

int deser_get_message(char const *const j_str, res_message_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    printf("[%s:%d]: parsing JSON message failed\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;
  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    ret = 0;
    goto end;
  }

  // allocate message object
  res->u.msg = core_message_new();
  if (!res->u.msg) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  // deserialize message object
  if ((ret = json_message_deserialize(json_obj, res->u.msg)) != 0) {
    printf("[%s:%d]: deserialize message error\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);

  return ret;
}

int get_message_by_id(iota_client_conf_t const *conf, char const msg_id[], res_message_t *res) {
  if (conf == NULL || msg_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(msg_id) != IOTA_MESSAGE_ID_HEX_BYTES) {
    // invalid message id length
    printf("[%s:%d]: invalid message id length: %zu\n", __func__, __LINE__, strlen(msg_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str = "/api/v2/messages/";

  cmd = iota_str_reserve(strlen(cmd_str) + IOTA_MESSAGE_ID_HEX_BYTES + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s", cmd_str, msg_id);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  byte_buf_t *http_res = NULL;
  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  int ret = -1;
  long st = 0;
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_message((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}
