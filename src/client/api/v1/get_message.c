// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_message.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

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

static int deser_tx_inputs(cJSON *essence_obj, payload_tx_t *payload_tx) {
  char const *const key_inputs = "inputs";
  char const *const key_tx_id = "transactionId";
  char const *const key_tx_out_idx = "transactionOutputIndex";

  cJSON *in_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, key_inputs);
  if (!in_obj) {
    printf("[%s:%d]: %s not found in the essence\n", __func__, __LINE__, key_inputs);
    return -1;
  }

  /*
  "inputs": [
      {
        "type": 0,
        "transactionId": "2bfbf7463b008c0298103121874f64b59d2b6172154aa14205db2ce0ba553b03",
        "transactionOutputIndex": 0
      }
    ],
  */
  if (cJSON_IsArray(in_obj)) {
    cJSON *elm = NULL;
    cJSON_ArrayForEach(elm, in_obj) {
      cJSON *tx_id_obj = cJSON_GetObjectItemCaseSensitive(elm, key_tx_id);
      cJSON *tx_out_idx = cJSON_GetObjectItemCaseSensitive(elm, key_tx_out_idx);
      if (tx_id_obj && tx_out_idx) {
        payload_tx_input_t input = {};
        char *str = cJSON_GetStringValue(tx_id_obj);
        if (str) {
          memcpy(input.tx_id, str, sizeof(input.tx_id));
        } else {
          printf("[%s:%d] encountered non-string array member", __func__, __LINE__);
          return -1;
        }

        if (cJSON_IsNumber(tx_out_idx)) {
          input.tx_output_index = tx_out_idx->valueint;
        } else {
          printf("[%s:%d] %s is not an number\n", __func__, __LINE__, key_tx_out_idx);
          return -1;
        }

        // add the input element to payload
        utarray_push_back(payload_tx->intputs, &input);

      } else {
        printf("[%s:%d] parsing inputs array failed\n", __func__, __LINE__);
        return -1;
      }
    }
  } else {
    printf("[%s:%d] %s is not an array object\n", __func__, __LINE__, key_inputs);
    return -1;
  }

  return 0;
}

static int deser_tx_outputs(cJSON *essence_obj, payload_tx_t *payload_tx) {
  char const *const key_outputs = "outputs";
  char const *const key_address = "address";
  char const *const key_addr_type = "type";
  char const *const key_amount = "amount";

  cJSON *out_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, key_outputs);
  if (!out_obj) {
    printf("[%s:%d]: %s not found in the essence\n", __func__, __LINE__, key_outputs);
    return -1;
  }

  /*
  "outputs": [
    { "type": 0,
      "address": {
        "type": 1,
        "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
      },
      "amount": 1000 } ],
  */
  if (cJSON_IsArray(out_obj)) {
    cJSON *elm = NULL;
    cJSON_ArrayForEach(elm, out_obj) {
      cJSON *tx_address_obj = cJSON_GetObjectItemCaseSensitive(elm, key_address);
      cJSON *tx_amount_obj = cJSON_GetObjectItemCaseSensitive(elm, key_amount);
      // check outputs/address and output/amount
      if (tx_address_obj && tx_amount_obj) {
        cJSON *addr_type = cJSON_GetObjectItemCaseSensitive(tx_address_obj, key_addr_type);
        if (addr_type) {
          // check outputs/address/type
          if (cJSON_IsNumber(addr_type) && addr_type->valueint == 1) {
            cJSON *addr = cJSON_GetObjectItemCaseSensitive(tx_address_obj, key_address);
            if (cJSON_IsString(addr) && cJSON_IsNumber(tx_amount_obj)) {
              payload_tx_output_t output = {};
              memcpy(output.address, addr->valuestring, sizeof(output.address));
              output.amount = (uint64_t)tx_amount_obj->valuedouble;
              // add the output element to payload
              utarray_push_back(payload_tx->outputs, &output);
            } else {
              printf("[%s:%d] address is not a string or amount is not an number\n", __func__, __LINE__);
              return -1;
            }

          } else {
            printf("[%s:%d] only support ed25519 address\n", __func__, __LINE__);
            return -1;
          }

        } else {
          printf("[%s:%d] parsing address type failed\n", __func__, __LINE__);
          return -1;
        }
      } else {
        printf("[%s:%d] parsing outputs array failed\n", __func__, __LINE__);
        return -1;
      }
    }
  } else {
    printf("[%s:%d] %s is not an array object\n", __func__, __LINE__, key_outputs);
    return -1;
  }
  return 0;
}

static int deser_tx_blocks(cJSON *blocks_obj, payload_tx_t *payload_tx) {
  char const *const key_blocks_sig = "signature";
  char const *const key_blocks_pub = "publicKey";
  char const *const key_blocks_sig_type = "type";

  /*
  "unlockBlocks": [{ "type": 0,
    "signature": {
      "type": 1,
      "publicKey": "dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a",
      "signature":
  "e625a71351bbccf87eeaad7e98f6a545306423b2aaf444792a1be8ccfdfe50b358583483c3dbc536b5842eeec381750c6b4495c14932be47c439a1a8ad242606"
  }}]
  */
  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, blocks_obj) {
    cJSON *sig_obj = cJSON_GetObjectItemCaseSensitive(elm, key_blocks_sig);
    if (sig_obj) {
      cJSON *sig_type = cJSON_GetObjectItemCaseSensitive(sig_obj, key_blocks_sig_type);
      if (cJSON_IsNumber(sig_type)) {
        if (sig_type->valueint == 1) {
          cJSON *pub = cJSON_GetObjectItemCaseSensitive(sig_obj, key_blocks_pub);
          cJSON *sig = cJSON_GetObjectItemCaseSensitive(sig_obj, key_blocks_sig);
          if (cJSON_IsString(pub) && cJSON_IsString(sig)) {
            payload_unlock_block_t block = {};
            memcpy(block.pub_key, pub->valuestring, sizeof(block.pub_key));
            memcpy(block.signature, sig->valuestring, sizeof(block.signature));
            // add to unlockBlocks
            utarray_push_back(payload_tx->unlock_blocks, &block);
          } else {
            printf("[%s:%d] publicKey or signature is not a string\n", __func__, __LINE__);
            return -1;
          }
        } else {
          printf("[%s:%d] only suppport ed25519 signature\n", __func__, __LINE__);
          return -1;
        }
      } else {
        printf("[%s:%d] signature type is not an number\n", __func__, __LINE__);
        return -1;
      }
    } else {
      printf("[%s:%d] %s is not found\n", __func__, __LINE__, key_blocks_sig);
      return -1;
    }
  }

  return 0;
}

static int deser_transaction(cJSON *tx_obj, res_message_t *res) {
  char const *const key_essence = "essence";
  char const *const key_payload = "payload";
  char const *const key_blocks = "unlockBlocks";
  int ret = 0;

  payload_tx_t *tx = payload_tx_new();
  if (tx == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  // parsing essence
  cJSON *essence_obj = cJSON_GetObjectItemCaseSensitive(tx_obj, key_essence);
  if (essence_obj) {
    // inputs array
    if ((ret = deser_tx_inputs(essence_obj, tx)) != 0) {
      goto end;
    }

    // outputs array
    if ((ret = deser_tx_outputs(essence_obj, tx)) != 0) {
      goto end;
    }

    // payload
    cJSON *payload_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, key_payload);
    if (!cJSON_IsNull(payload_obj)) {
      // TODO;
      printf("[%s:%d]: TODO parsing payload in a transaction\n", __func__, __LINE__);
    }

    // unlock blocks
    cJSON *blocks_obj = cJSON_GetObjectItemCaseSensitive(tx_obj, key_blocks);
    if (cJSON_IsArray(blocks_obj)) {
      ret = deser_tx_blocks(blocks_obj, tx);
    } else {
      printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, key_blocks);
      ret = -1;
    }

  } else {
    printf("[%s:%d]: %s not found in the message\n", __func__, __LINE__, key_essence);
    ret = -1;
  }

end:
  if (ret != 0) {
    payload_tx_free(tx);
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
    return msg;
  }
  return NULL;
}

void res_message_free(res_message_t *msg) {
  if (msg) {
    if (msg->is_error) {
      res_err_free(msg->u.error);
    } else {
      api_message_free(msg->u.msg);
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
  char const *const key_data = "data";

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
    res->u.msg = api_message_new();
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
        case MSG_PAYLOAD_TRANSACTION:
          deser_transaction(payload, res);
          break;
        case MSG_PAYLOAD_MILESTONE:
          deser_milestone(payload, res);
          break;
        case MSG_PAYLOAD_INDEXATION:
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
    if (!res->is_error && res->u.msg->type == MSG_PAYLOAD_MILESTONE) {
      payload_milestone_t *milestone = (payload_milestone_t *)res->u.msg->payload;
      return utarray_len(milestone->signatures);
    }
  }
  return 0;
}

char *get_message_milestone_signature(res_message_t const *const res, size_t index) {
  if (res) {
    if (!res->is_error && res->u.msg->type == MSG_PAYLOAD_MILESTONE) {
      payload_milestone_t *milestone = (payload_milestone_t *)res->u.msg->payload;
      if (utarray_len(milestone->signatures)) {
        char **p = (char **)utarray_eltptr(milestone->signatures, index);
        return *p;
      }
    }
  }
  return NULL;
}

msg_payload_type_t get_message_payload_type(res_message_t const *const res) {
  if (res) {
    if (!res->is_error) {
      return res->u.msg->type;
    }
  }
  return MSG_PAYLOAD_UNKNOW;
}
