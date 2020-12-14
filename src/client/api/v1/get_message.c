// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_message.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

static payload_milestone_t *payload_milestone_new() {
  payload_milestone_t *ms = malloc(sizeof(payload_milestone_t));
  if (ms) {
    utarray_new(ms->signatures, &ut_str_icd);
    ms->index = 0;
    ms->timestamp = 0;
    memset(ms->inclusion_merkle_proof, 0, sizeof(ms->inclusion_merkle_proof));
  }
  return ms;
}

static void payload_milestone_free(payload_milestone_t *ms) {
  if (ms) {
    if (ms->signatures) {
      utarray_free(ms->signatures);
    }
    free(ms);
  }
}

static payload_index_t *payload_index_new() {
  payload_index_t *idx = malloc(sizeof(payload_index_t));
  if (idx) {
    idx->data = byte_buf_new();
    if (idx->data) {
      idx->index = byte_buf_new();
      if (idx->index) {
        return idx;
      }
      byte_buf_free(idx->data);
      free(idx);
      return NULL;
    }
    free(idx);
    return NULL;
  }
  return NULL;
}

static void payload_index_free(payload_index_t *idx) {
  if (idx) {
    byte_buf_free(idx->data);
    byte_buf_free(idx->index);
    free(idx);
  }
}

static get_message_t *get_message_new() {
  get_message_t *msg = malloc(sizeof(get_message_t));
  memset(msg->net_id, 0, sizeof(msg->net_id));
  memset(msg->parent1, 0, sizeof(msg->parent1));
  memset(msg->parent2, 0, sizeof(msg->parent2));
  memset(msg->nonce, 0, sizeof(msg->nonce));
  msg->payload = NULL;
  msg->type = 255;  // invalid payload type
  return msg;
}

static void get_message_free(get_message_t *msg) {
  if (msg) {
    switch (msg->type) {
      case MSG_UNSIGNED_TX:
        // TODO
        break;
      case MSG_MILESTONE:
        payload_milestone_free((payload_milestone_t *)msg->payload);
        break;
      case MSG_INDEXATION:
        payload_index_free((payload_index_t *)msg->payload);
        break;
      default:
        // do nothing
        break;
    }
    free(msg);
  }
}

static int deser_milestone(cJSON *milestone, res_message_t *res) {
  char const *const key_index = "index";
  char const *const key_timestamp = "timestamp";
  char const *const key_inclusion = "inclusionMerkleProof";
  char const *const key_signatures = "signatures";
  int ret = 0;
  payload_milestone_t *ms = payload_milestone_new();
  if (ms == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  // parsing index
  if ((ret = json_get_uint32(milestone, key_index, &ms->index)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, key_index);
    ret = -1;
    goto end;
  }

  // parsing timestamp
  if ((ret = json_get_uint64(milestone, key_timestamp, &ms->timestamp)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, key_timestamp);
    ret = -1;
    goto end;
  }

  // parsing inclusion Merkle proof
  if ((ret = json_get_string(milestone, key_inclusion, ms->inclusion_merkle_proof,
                             sizeof(ms->inclusion_merkle_proof))) != 0) {
    printf("[%s:%d]: parsing %s string failed\n", __func__, __LINE__, key_inclusion);
    ret = -1;
    goto end;
  }

  // parsing signatures
  if ((ret = json_string_array_to_utarray(milestone, key_signatures, ms->signatures)) != 0) {
    printf("[%s:%d]: parsing %s array failed\n", __func__, __LINE__, key_signatures);
    ret = -1;
  }

end:
  if (ret != 0) {
    payload_milestone_free(ms);
    res->u.msg->payload = NULL;
  } else {
    res->u.msg->payload = (void *)ms;
  }

  return ret;
}

static int deser_indexation(cJSON *idx_obj, res_message_t *res) {
  char const *const key_index = "index";
  char const *const key_data = "data";
  int ret = 0;
  payload_index_t *idx = payload_index_new();
  if (idx == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  if ((ret = json_get_byte_buf_str(idx_obj, key_index, idx->index)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_index);
    ret = -1;
    goto end;
  }

  if ((ret = json_get_byte_buf_str(idx_obj, key_data, idx->data)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_data);
    ret = -1;
  }

end:
  if (ret != 0) {
    payload_index_free(idx);
    res->u.msg->payload = NULL;
  } else {
    res->u.msg->payload = (void *)idx;
  }

  return ret;
}

res_message_t *res_message_new() {
  res_message_t *msg = malloc(sizeof(res_message_t));
  if (msg) {
    msg->is_error = false;
    return msg;
  }
  return NULL;
}

void res_message_free(res_message_t *msg) {
  if (msg) {
    if (msg->is_error) {
      res_err_free(msg->u.error);
    } else {
      get_message_free(msg->u.msg);
    }
    free(msg);
  }
}

int deser_get_message(char const *const j_str, res_message_t *res) {
  char const *const key_net = "networkId";
  char const *const key_p1_id = "parent1MessageId";
  char const *const key_p2_id = "parent2MessageId";
  char const *const key_nonce = "nonce";
  char const *const key_payload = "payload";
  char const *const key_type = "type";

  int ret = 0;
  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    goto end;
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    // new message object
    res->u.msg = get_message_new();
    if (!res->u.msg) {
      printf("[%s:%d]: OOM\n", __func__, __LINE__);
      ret = -1;
      goto end;
    }

    // network ID
    if ((ret = json_get_string(data_obj, key_net, res->u.msg->net_id, sizeof(res->u.msg->net_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_net);
      ret = -1;
      goto end;
    }

    // parent1MessageId
    if ((ret = json_get_string(data_obj, key_p1_id, res->u.msg->parent1, sizeof(res->u.msg->parent1))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_p1_id);
      ret = -1;
      goto end;
    }

    // parent2MessageId
    if ((ret = json_get_string(data_obj, key_p2_id, res->u.msg->parent2, sizeof(res->u.msg->parent2))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_p2_id);
      ret = -1;
      goto end;
    }

    // nonce
    if ((ret = json_get_string(data_obj, key_nonce, res->u.msg->nonce, sizeof(res->u.msg->nonce))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_nonce);
      ret = -1;
      goto end;
    }

    cJSON *payload = cJSON_GetObjectItemCaseSensitive(data_obj, key_payload);
    if (payload) {
      if ((ret = json_get_uint32(payload, key_type, &res->u.msg->type) != 0)) {
        printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, key_type);
        ret = -1;
        goto end;
      }

      switch (res->u.msg->type) {
        case MSG_UNSIGNED_TX:
          // TODO
          break;
        case MSG_MILESTONE:
          deser_milestone(payload, res);
          break;
        case MSG_INDEXATION:
          deser_indexation(payload, res);
          break;
        default:
          // do nothing
          break;
      }

    } else {
      printf("[%s:%d]: invalid message: payload not found\n", __func__, __LINE__);
      ret = -1;
      goto end;
    }
  }

end:
  cJSON_Delete(json_obj);

  return ret;
}

int get_message_by_id(iota_client_conf_t const *conf, char const msg_id[], res_message_t *res) {
  int ret = 0;
  if (conf == NULL || msg_id == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }

  if (strlen(msg_id) != 64) {
    // invalid output id length
    printf("[%s:%d]: invalid output id length: %zu\n", __func__, __LINE__, strlen(msg_id));
    return -1;
  }

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);
  if (cmd == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, "api/v1/messages/")) {
    printf("[%s:%d]: cmd append failed\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, msg_id)) {
    printf("[%s:%d]: output id append failed\n", __func__, __LINE__);
    return -1;
  }

  // http client configuration
  http_client_config_t http_conf = {0};
  http_conf.url = cmd->buf;
  if (conf->port) {
    http_conf.port = conf->port;
  }

  byte_buf_t *http_res = byte_buf_new();
  if (http_res == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    ret = -1;
    goto done;
  }

  // send request via http client
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

size_t get_message_milestone_signature_count(res_message_t const *const res) {
  if (res) {
    if (!res->is_error && res->u.msg->type == MSG_MILESTONE) {
      payload_milestone_t *milestone = (payload_milestone_t *)res->u.msg->payload;
      return utarray_len(milestone->signatures);
    }
  }
  return 0;
}

char *get_message_milestone_signature(res_message_t const *const res, size_t index) {
  if (res) {
    if (!res->is_error && res->u.msg->type == MSG_MILESTONE) {
      payload_milestone_t *milestone = (payload_milestone_t *)res->u.msg->payload;
      if (utarray_len(milestone->signatures)) {
        char **p = (char **)utarray_eltptr(milestone->signatures, index);
        return *p;
      }
    }
  }
  return NULL;
}
