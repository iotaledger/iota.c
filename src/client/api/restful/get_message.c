// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_utils.h"
#include "client/api/restful/get_message.h"
#include "client/network/http.h"
#include "core/address.h"
#include "core/utils/iota_str.h"

static int deser_milestone(cJSON *milestone, res_message_t *res) {
  if (milestone == NULL || res == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;
  milestone_t *ms = payload_milestone_new();
  if (ms == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  // parsing index
  if ((ret = json_get_uint64(milestone, JSON_KEY_INDEX, &ms->index)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_INDEX);
    goto end;
  }

  // parsing timestamp
  if ((ret = json_get_uint64(milestone, JSON_KEY_TIMESTAMP, &ms->timestamp)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    goto end;
  }

  // parsing inclusion Merkle proof
  if ((ret = json_get_string(milestone, JSON_KEY_INCLUSION_MKL, ms->inclusion_merkle_proof,
                             sizeof(ms->inclusion_merkle_proof))) != 0) {
    printf("[%s:%d]: parsing %s string failed\n", __func__, __LINE__, JSON_KEY_INCLUSION_MKL);
    goto end;
  }

  // parsing signatures
  if ((ret = json_string_array_to_utarray(milestone, JSON_KEY_SIGNATURES, ms->signatures)) != 0) {
    printf("[%s:%d]: parsing %s array failed\n", __func__, __LINE__, JSON_KEY_SIGNATURES);
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

static int deser_tx_indexation(cJSON *json, indexation_t *idx) {
  if (json == NULL || idx == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;
  if ((ret = json_get_byte_buf_str(json, JSON_KEY_INDEX, idx->index)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_INDEX);
  } else {
    if ((ret = json_get_byte_buf_str(json, JSON_KEY_DATA, idx->data)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_DATA);
    }
  }
  return ret;
}

static int deser_msg_indexation(cJSON *idx_obj, res_message_t *res) {
  if (idx_obj == NULL || res == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  indexation_t *idx = indexation_new();
  if (idx == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;
  ret = deser_tx_indexation(idx_obj, idx);
  if (ret != 0) {
    indexation_free(idx);
    res->u.msg->payload = NULL;
  } else {
    res->u.msg->payload = (void *)idx;
  }

  return ret;
}

static int deser_tx_inputs(cJSON *essence_obj, transaction_payload_t *payload_tx) {
  if (essence_obj == NULL || payload_tx == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *in_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_INPUTS);
  if (!in_obj) {
    printf("[%s:%d]: %s not found in the essence\n", __func__, __LINE__, JSON_KEY_INPUTS);
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
      cJSON *tx_id_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TX_ID);
      cJSON *tx_out_idx = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TX_OUT_INDEX);
      if (tx_id_obj && tx_out_idx) {
        // FIXME
        /*
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
          printf("[%s:%d] %s is not an number\n", __func__, __LINE__, JSON_KEY_TX_OUT_INDEX);
          return -1;
        }

        // add the input element to payload
        utarray_push_back(payload_tx->inputs, &input);*/

      } else {
        printf("[%s:%d] parsing inputs array failed\n", __func__, __LINE__);
        return -1;
      }
    }
  } else {
    printf("[%s:%d] %s is not an array object\n", __func__, __LINE__, JSON_KEY_INPUTS);
    return -1;
  }

  return 0;
}

static int deser_tx_outputs(cJSON *essence_obj, transaction_payload_t *payload_tx) {
  if (essence_obj == NULL || payload_tx == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *out_obj = cJSON_GetObjectItemCaseSensitive(essence_obj, JSON_KEY_OUTPUTS);
  if (!out_obj) {
    printf("[%s:%d]: %s not found in the essence\n", __func__, __LINE__, JSON_KEY_OUTPUTS);
    return -1;
  }

  /*
  Example for extended output:
  "outputs": [
    { "type": 3,
      "amount": 10000000,
      "nativeTokens": [],
      "unlockConditions": [],
      "blocks": [] }
  ],
  */
  if (cJSON_IsArray(out_obj)) {
    cJSON *elm = NULL;
    cJSON_ArrayForEach(elm, out_obj) {
      cJSON *tx_type_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TYPE);

      // check output type
      if (!cJSON_IsNumber(tx_type_obj)) {
        printf("[%s:%d] %s must be a number\n", __func__, __LINE__, JSON_KEY_TYPE);
        break;
      }
      // FIXME
      /*
      int res = -1;
      if (tx_type_obj->valueint == OUTPUT_EXTENDED) {
        res = deser_message_tx_extended_output(elm, payload_tx);
      } else if (tx_type_obj->valueint == OUTPUT_ALIAS) {
        res = deser_message_tx_alias_output(elm, payload_tx);
      } else if (tx_type_obj->valueint == OUTPUT_FOUNDRY) {
        res = deser_message_tx_foundry_output(elm, payload_tx);
      } else if (tx_type_obj->valueint == OUTPUT_NFT) {
        res = deser_message_tx_nft_output(elm, payload_tx);
      } else {
        printf("[%s:%d] Unsupported output block type\n", __func__, __LINE__);
        break;
      }*/
    }
  } else {
    printf("[%s:%d] %s is not an array object\n", __func__, __LINE__, JSON_KEY_OUTPUTS);
    return -1;
  }
  return 0;
}

static int deser_tx_blocks(cJSON *blocks_obj, transaction_payload_t *payload_tx) {
  if (blocks_obj == NULL || payload_tx == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

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
    cJSON *block_type = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TYPE);
    if (!cJSON_IsNumber(block_type)) {
      printf("[%s:%d] %s must be a number\n", __func__, __LINE__, JSON_KEY_TYPE);
      break;
    }
    if (block_type->valueint == 0) {  // signature block
      cJSON *sig_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_SIG);
      if (sig_obj) {
        cJSON *sig_type = cJSON_GetObjectItemCaseSensitive(sig_obj, JSON_KEY_TYPE);
        if (cJSON_IsNumber(sig_type)) {
          if (sig_type->valueint == ADDRESS_TYPE_ED25519) {
            cJSON *pub = cJSON_GetObjectItemCaseSensitive(sig_obj, JSON_KEY_PUB_KEY);
            cJSON *sig = cJSON_GetObjectItemCaseSensitive(sig_obj, JSON_KEY_SIG);
            if (cJSON_IsString(pub) && cJSON_IsString(sig)) {
              // FIXME
              /*char sig_block[API_SIGNATURE_BLOCK_STR_LEN] = {};
              sig_block[0] = sig_type->valueint;
              memcpy(sig_block + 1, pub->valuestring, API_PUB_KEY_HEX_STR_LEN);
              memcpy(sig_block + 1 + API_PUB_KEY_HEX_STR_LEN, sig->valuestring, API_SIGNATURE_HEX_STR_LEN);
              payload_tx_add_sig_block(payload_tx, sig_block, API_SIGNATURE_BLOCK_STR_LEN);*/
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
        printf("[%s:%d] %s is not found\n", __func__, __LINE__, JSON_KEY_SIG);
        return -1;
      }
    } else if (block_type->valueint == 1) {  // reference block
      cJSON *ref = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_REFERENCE);
      if (ref && cJSON_IsNumber(ref)) {
        // FIXME
        // payload_tx_add_ref_block(payload_tx, ref->valueint);
      }
    } else {
      printf("[%s:%d] Unsupported block type\n", __func__, __LINE__);
      break;
    }
  }

  return 0;
}

static int deser_transaction(cJSON *tx_obj, res_message_t *res) {
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
    if ((ret = deser_tx_inputs(essence_obj, tx)) != 0) {
      goto end;
    }

    // outputs array
    if ((ret = deser_tx_outputs(essence_obj, tx)) != 0) {
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
        if (payload_type->valueint == MSG_PAYLOAD_INDEXATION) {
          indexation_t *idx = indexation_new();
          if (idx == NULL) {
            printf("[%s:%d]: allocate index payload failed\n", __func__, __LINE__);
          } else {
            if (deser_tx_indexation(payload_obj, idx) != 0) {
              printf("[%s:%d]: parsing index payload failed\n", __func__, __LINE__);
              indexation_free(idx);
            } else {
              tx->type = MSG_PAYLOAD_INDEXATION;
              tx->essence->payload = idx;
            }
          }
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
      ret = deser_tx_blocks(blocks_obj, tx);
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

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_DATA);
  if (data_obj) {
    // new message object
    res->u.msg = core_message_new();
    if (!res->u.msg) {
      printf("[%s:%d]: OOM\n", __func__, __LINE__);
      goto end;
    }

    // network ID
    char network_id[32];
    if ((ret = json_get_string(data_obj, JSON_KEY_NET_ID, network_id, sizeof(network_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NET_ID);
      goto end;
    }
    sscanf(network_id, "%" SCNu64, &res->u.msg->network_id);

    // parentMessageIds
    if ((ret = json_string_array_to_utarray(data_obj, JSON_KEY_PARENT_IDS, res->u.msg->parents)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
      utarray_free(res->u.msg->parents);
      res->u.msg->parents = NULL;
      goto end;
    }

    // nonce
    char nonce[32];
    if ((ret = json_get_string(data_obj, JSON_KEY_NONCE, nonce, sizeof(nonce))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NONCE);
      goto end;
    }
    sscanf(nonce, "%" SCNu64, &res->u.msg->nonce);

    cJSON *payload = cJSON_GetObjectItemCaseSensitive(data_obj, JSON_KEY_PAYLOAD);
    if (payload) {
      if ((ret = json_get_uint32(payload, JSON_KEY_TYPE, &res->u.msg->payload_type) != 0)) {
        printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_TYPE);
        goto end;
      }

      switch (res->u.msg->payload_type) {
        case MSG_PAYLOAD_TRANSACTION:
          ret = deser_transaction(payload, res);
          break;
        case MSG_PAYLOAD_MILESTONE:
          ret = deser_milestone(payload, res);
          break;
        case MSG_PAYLOAD_INDEXATION:
          ret = deser_msg_indexation(payload, res);
          break;
        default:
          // do nothing
          break;
      }

    } else {
      printf("[%s:%d]: invalid message: payload not found\n", __func__, __LINE__);
    }
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
  char const *const cmd_str = "/api/v1/messages/";

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

size_t get_message_milestone_signature_count(res_message_t const *const res) {
  if (res) {
    if (!res->is_error && res->u.msg->payload_type == MSG_PAYLOAD_MILESTONE) {
      milestone_t *milestone = (milestone_t *)res->u.msg->payload;
      return utarray_len(milestone->signatures);
    }
  }
  return 0;
}

char *get_message_milestone_signature(res_message_t const *const res, size_t index) {
  if (res) {
    if (!res->is_error && res->u.msg->payload_type == MSG_PAYLOAD_MILESTONE) {
      milestone_t *milestone = (milestone_t *)res->u.msg->payload;
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
      return res->u.msg->payload_type;
    }
  }
  return MSG_PAYLOAD_UNKNOW;
}
