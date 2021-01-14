// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_output.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

int get_output(iota_client_conf_t const *conf, char const output_id[], res_output_t *res) {
  int ret = -1;
  long st = 0;
  byte_buf_t *http_res = NULL;

  if (conf == NULL || output_id == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }

  if (strlen(output_id) != IOTA_OUTPUT_ID_HEX_BYTES) {
    // invalid output id length
    printf("[%s:%d]: invalid output id length: %zu\n", __func__, __LINE__, strlen(output_id));
    return -1;
  }

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);
  if (cmd == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, "api/v1/outputs/")) {
    printf("[%s:%d]: cmd append failed\n", __func__, __LINE__);
    goto done;
  }

  if (iota_str_append(cmd, output_id)) {
    printf("[%s:%d]: output id append failed\n", __func__, __LINE__);
    goto done;
  }

  // http client configuration
  http_client_config_t http_conf = {0};
  http_conf.url = cmd->buf;
  if (conf->port) {
    http_conf.port = conf->port;
  }

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_output((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

int deser_get_output(char const *const j_str, res_output_t *res) {
  char const *const key_msg_id = "messageId";
  char const *const key_tx_id = "transactionId";
  char const *const key_output_idx = "outputIndex";
  char const *const key_output = "output";
  char const *const key_is_spent = "isSpent";
  char const *const key_addr = "address";
  char const *const key_type = "type";
  char const *const key_amount = "amount";

  int ret = -1;
  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    ret = 0;
    goto end;
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    // message ID
    if ((ret = json_get_string(data_obj, key_msg_id, res->u.output.msg_id, sizeof(res->u.output.msg_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_msg_id);
      goto end;
    }

    // transaction ID
    if ((ret = json_get_string(data_obj, key_tx_id, res->u.output.tx_id, sizeof(res->u.output.tx_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_tx_id);
      goto end;
    }

    // output index
    if ((ret = json_get_uint16(data_obj, key_output_idx, &res->u.output.output_idx)) != 0) {
      printf("[%s:%d]: gets %s json uint16 failed\n", __func__, __LINE__, key_output_idx);
      goto end;
    }

    // is spent
    if ((ret = json_get_boolean(data_obj, key_is_spent, &res->u.output.is_spent)) != 0) {
      printf("[%s:%d]: gets %s json bool failed\n", __func__, __LINE__, key_is_spent);
      goto end;
    }

    cJSON *output_obj = cJSON_GetObjectItemCaseSensitive(data_obj, key_output);
    if (output_obj) {
      // output type
      if ((ret = json_get_uint32(output_obj, key_type, &res->u.output.output_type)) != 0) {
        printf("[%s:%d]: gets output %s failed\n", __func__, __LINE__, key_type);
        goto end;
      }
      // amount
      if ((ret = json_get_uint64(output_obj, key_amount, &res->u.output.amount)) != 0) {
        printf("[%s:%d]: gets output %s failed\n", __func__, __LINE__, key_amount);
        goto end;
      }

      cJSON *addr_obj = cJSON_GetObjectItemCaseSensitive(output_obj, key_addr);
      if (addr_obj) {
        // address type
        if ((ret = json_get_uint32(addr_obj, key_type, &res->u.output.address_type)) != 0) {
          printf("[%s:%d]: gets address %s failed\n", __func__, __LINE__, key_type);
          goto end;
        }

        // address
        if ((ret = json_get_string(addr_obj, key_addr, res->u.output.addr, sizeof(res->u.output.addr))) != 0) {
          printf("[%s:%d]: gets %s string failed\n", __func__, __LINE__, key_addr);
          goto end;
        }
      }
    }
  }

end:
  cJSON_Delete(json_obj);

  return ret;
}

void dump_output_response(res_output_t *res) {
  if (!res) {
    return;
  }
  if (res->is_error) {
    printf("Error: %s\n", res->u.error->msg);
  } else {
    get_output_t *output = &res->u.output;
    printf("output:[\n");
    printf("\t%s addr: %.64s\n", output->address_type ? "ED25519" : "WOTS", output->addr);
    printf("\tmsg id: %.64s\n", output->msg_id);
    printf("\ttx id: %.64s\n", output->tx_id);
    printf("\tamount: %" PRIu64 "\n", output->amount);
    printf("\toutput_idx: %" PRIu16 "\n", output->output_idx);
    printf("\tis spent: %s\n", output->is_spent ? "True" : "False");
    printf("]\n");
  }
}
