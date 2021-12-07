// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/events/sub_address_outputs.h"
#include "client/api/json_utils.h"

int event_parse_address_outputs(char const data[], event_addr_outputs_t *res) {
  int ret = -1;
  cJSON *json_obj = cJSON_Parse(data);
  if (json_obj == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return ret;
  }

  // message ID
  if ((ret = json_get_string(json_obj, JSON_KEY_MSG_ID, res->msg_id, sizeof(res->msg_id))) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
    goto end;
  }

  // transaction ID
  if ((ret = json_get_string(json_obj, JSON_KEY_TX_ID, res->tx_id, sizeof(res->tx_id))) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_TX_ID);
    goto end;
  }

  // output index
  if ((ret = json_get_uint16(json_obj, JSON_KEY_OUTPUT_IDX, &res->output_index)) != 0) {
    printf("[%s:%d]: gets %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_OUTPUT_IDX);
    goto end;
  }

  // is spent
  if ((ret = json_get_boolean(json_obj, JSON_KEY_IS_SPENT, &res->is_spent)) != 0) {
    printf("[%s:%d]: gets %s json bool failed\n", __func__, __LINE__, JSON_KEY_IS_SPENT);
    goto end;
  }

  // ledgerIndex
  if ((ret = json_get_uint64(json_obj, JSON_KEY_LEDGER_IDX, &res->ledger_index)) != 0) {
    printf("[%s:%d]: gets %s json uint64 failed\n", __func__, __LINE__, JSON_KEY_LEDGER_IDX);
    goto end;
  }

  // output object
  cJSON *j_output = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_OUTPUT);
  if (j_output) {
    if ((ret = json_get_uint32(j_output, JSON_KEY_TYPE, &res->output.output_type)) != 0) {
      printf("[%s:%d]: gets %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      goto end;
    }

    // amount
    if ((ret = json_get_uint64(j_output, JSON_KEY_AMOUNT, &res->output.amount)) != 0) {
      printf("[%s:%d]: gets %s json uint64 failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
      goto end;
    }

    // address object
    cJSON *j_addr = cJSON_GetObjectItemCaseSensitive(j_output, JSON_KEY_ADDR);
    if (j_addr) {
      // ed25519 address
      if ((ret = json_get_string(j_addr, JSON_KEY_ADDR, res->output.addr, sizeof(res->output.addr))) != 0) {
        printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_ADDR);
        goto end;
      }
    } else {
      printf("[%s:%d]: address object not found\n", __func__, __LINE__);
      ret = -1;
      goto end;
    }
  } else {
    printf("[%s:%d]: output object not found\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

end:

  cJSON_Delete(json_obj);
  return ret;
}

int event_sub_address_outputs(event_client_handle_t client, int *mid, char const addr[], bool is_bech32, int qos) {
  // 91 is the max length of string addresses/ed25519/[addr_str]/outputs
  char topic_buff[91] = {};
  if (is_bech32) {
    sprintf(topic_buff, "addresses/%s/outputs", addr);
  } else {
    sprintf(topic_buff, "addresses/ed25519/%s/outputs", addr);
  }
  return event_subscribe(client, mid, topic_buff, qos);
}

int event_sub_outputs_id(event_client_handle_t client, int *mid, char const output_id[], int qos) {
  if ((strlen(output_id)) != OUTPUT_ID_LEN) {
    printf("[%s:%d]: Output Id length is invalid\n", __func__, __LINE__);
    return 0;
  }

  // Buffer enough for outputs/{outputId}
  char topic_buff[77] = {};
  sprintf(topic_buff, "outputs/%s", output_id);

  return event_subscribe(client, mid, topic_buff, qos);
}