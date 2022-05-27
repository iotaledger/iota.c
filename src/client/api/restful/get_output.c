// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/json_parser/outputs/features.h"
#include "client/api/json_parser/outputs/native_tokens.h"
#include "client/api/json_parser/outputs/output_alias.h"
#include "client/api/json_parser/outputs/output_basic.h"
#include "client/api/json_parser/outputs/output_foundry.h"
#include "client/api/json_parser/outputs/output_nft.h"
#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "client/api/restful/get_output.h"
#include "client/constants.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

// deserialize json object to an output object
static int json_output_deserialize(cJSON *output_obj, utxo_output_t **output) {
  if (output_obj == NULL || *output != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  utxo_output_t *tmp_output = malloc(sizeof(utxo_output_t));
  if (!tmp_output) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }
  tmp_output->output = NULL;

  // output type
  if (json_get_uint32(output_obj, JSON_KEY_TYPE, &tmp_output->output_type) != 0) {
    printf("[%s:%d]: gets output %s failed\n", __func__, __LINE__, JSON_KEY_TYPE);
    free(tmp_output);
    return -1;
  }

  int ret = -1;

  switch (tmp_output->output_type) {
    case OUTPUT_BASIC: {
      output_basic_t *basic_output = tmp_output->output;
      ret = json_output_basic_deserialize(output_obj, &basic_output);
      tmp_output->output = basic_output;
      break;
    }
    case OUTPUT_ALIAS: {
      output_alias_t *alias_output = tmp_output->output;
      ret = json_output_alias_deserialize(output_obj, &alias_output);
      tmp_output->output = alias_output;
      break;
    }
    case OUTPUT_FOUNDRY: {
      output_foundry_t *foundry_output = tmp_output->output;
      ret = json_output_foundry_deserialize(output_obj, &foundry_output);
      tmp_output->output = foundry_output;
      break;
    }
    case OUTPUT_NFT: {
      output_nft_t *nft_output = tmp_output->output;
      ret = json_output_nft_deserialize(output_obj, &nft_output);
      tmp_output->output = nft_output;
      break;
    }
    default:
      printf("[%s:%d]: unsupported output type\n", __func__, __LINE__);
      ret = -1;
      break;
  }

  if (ret == 0) {
    *output = tmp_output;
  } else {
    free(tmp_output);
  }

  return ret;
}

get_output_t *get_output_new() {
  get_output_t *output = malloc(sizeof(get_output_t));
  if (output) {
    memset(output, 0, sizeof(get_output_t));
    return output;
  }
  return NULL;
}

void get_output_free(get_output_t *res) {
  if (res) {
    if (res->output) {
      switch (res->output->output_type) {
        case OUTPUT_SINGLE_OUTPUT:
        case OUTPUT_DUST_ALLOWANCE:
        case OUTPUT_TREASURY:
          printf("[%s:%d] deprecated or unsupported output type must not be used\n", __func__, __LINE__);
          break;
        case OUTPUT_BASIC:
          output_basic_free((output_basic_t *)res->output->output);
          break;
        case OUTPUT_ALIAS:
          output_alias_free((output_alias_t *)res->output->output);
          break;
        case OUTPUT_FOUNDRY:
          output_foundry_free((output_foundry_t *)res->output->output);
          break;
        case OUTPUT_NFT:
          output_nft_free((output_nft_t *)res->output->output);
          break;
      }
      free(res->output);
    }
    free(res);
  }
}

res_output_t *get_output_response_new() {
  res_output_t *output = malloc(sizeof(res_output_t));
  if (output) {
    output->is_error = false;
    output->u.data = NULL;
    return output;
  }
  return NULL;
}

void get_output_response_free(res_output_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      get_output_free(res->u.data);
    }
    free(res);
  }
}

int get_output(iota_client_conf_t const *conf, char const output_id[], res_output_t *res) {
  int ret = -1;
  long st = 0;
  byte_buf_t *http_res = NULL;

  if (conf == NULL || output_id == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }

  if (strlen(output_id) != BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES)) {
    // invalid output id length
    printf("[%s:%d]: invalid output id length: %zu\n", __func__, __LINE__, strlen(output_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str = "/outputs/0x";
  // reserver buffer enough for NODE_API_PATH + cmd_info + BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES) + 1
  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_str) + BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s", NODE_API_PATH, cmd_str, output_id);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

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

int get_output_meta(iota_client_conf_t const *conf, char const output_id[], res_output_t *res) {
  int ret = -1;
  long st = 0;
  byte_buf_t *http_res = NULL;

  if (conf == NULL || output_id == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }

  if (strlen(output_id) != BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES)) {
    // invalid output id length
    printf("[%s:%d]: invalid output id length: %zu\n", __func__, __LINE__, strlen(output_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_pre = "/outputs/0x";
  char const *const cmd_post = "/metadata";

  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_pre) + strlen(cmd_post) +
                         BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s%s", NODE_API_PATH, cmd_pre, output_id, cmd_post);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_output_meta((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

int parse_get_output(char const *const j_str, get_output_t *res) {
  int ret = -1;
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  // metadata object
  cJSON *json_metadata_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_METADATA);
  if (!json_metadata_obj) {
    printf("[%s:%d]: gets %s json object failed\n", __func__, __LINE__, JSON_KEY_METADATA);
    goto end;
  }
  if ((ret = parse_get_output_meta(json_metadata_obj, res)) != 0) {
    printf("[%s:%d]: failed to parse output metadata\n", __func__, __LINE__);
    goto end;
  }

  // output object
  cJSON *output_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_OUTPUT);
  if (!output_obj) {
    printf("[%s:%d]: gets %s json object failed\n", __func__, __LINE__, JSON_KEY_OUTPUT);
    goto end;
  }
  if ((ret = json_output_deserialize(output_obj, &res->output)) != 0) {
    printf("[%s:%d]: failed to deserialize output object\n", __func__, __LINE__);
    goto end;
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int parse_get_output_meta(cJSON *json_obj, get_output_t *res) {
  int ret = -1;
  if (json_obj == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  // block ID
  if ((ret = json_get_hex_str_to_bin(json_obj, JSON_KEY_BLOCK_ID, res->meta.blk_id, sizeof(res->meta.blk_id))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_BLOCK_ID);
    goto end;
  }

  // transaction ID
  if ((ret = json_get_hex_str_to_bin(json_obj, JSON_KEY_TX_ID, res->meta.tx_id, sizeof(res->meta.tx_id))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_TX_ID);
    goto end;
  }

  // output index
  if ((ret = json_get_uint16(json_obj, JSON_KEY_OUTPUT_IDX, &res->meta.output_index)) != 0) {
    printf("[%s:%d]: gets %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_OUTPUT_IDX);
    goto end;
  }

  // is spent
  if ((ret = json_get_boolean(json_obj, JSON_KEY_IS_SPENT, &res->meta.is_spent)) != 0) {
    printf("[%s:%d]: gets %s json bool failed\n", __func__, __LINE__, JSON_KEY_IS_SPENT);
    goto end;
  }

  if (res->meta.is_spent) {
    // milestoneIndexSpent
    if ((ret = json_get_uint32(json_obj, JSON_KEY_MILESTONE_INDEX_SPENT, &res->meta.ml_index_spent)) != 0) {
      printf("[%s:%d]: gets %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_MILESTONE_INDEX_SPENT);
      goto end;
    }
    // milestoneTimestampSpent
    if ((ret = json_get_uint32(json_obj, JSON_KEY_MILESTONE_TIME_SPENT, &res->meta.ml_time_spent)) != 0) {
      printf("[%s:%d]: gets %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_MILESTONE_TIME_SPENT);
      goto end;
    }
    // transactionIdSpent
    if ((ret = json_get_hex_str_to_bin(json_obj, JSON_KEY_TX_ID_SPENT, res->meta.tx_id_spent,
                                       sizeof(res->meta.tx_id_spent))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_TX_ID_SPENT);
      goto end;
    }
  }

  // milestoneIndexBooked
  if ((ret = json_get_uint32(json_obj, JSON_KEY_MILESTONE_INDEX_BOOKED, &res->meta.ml_index_booked)) != 0) {
    printf("[%s:%d]: gets %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_MILESTONE_INDEX_BOOKED);
    goto end;
  }

  // milestoneTimestampBooked
  if ((ret = json_get_uint32(json_obj, JSON_KEY_MILESTONE_TIME_BOOKED, &res->meta.ml_time_booked)) != 0) {
    printf("[%s:%d]: gets %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_MILESTONE_TIME_BOOKED);
    goto end;
  }

  // ledgerIndex
  if ((ret = json_get_uint32(json_obj, JSON_KEY_LEDGER_IDX, &res->meta.ledger_index)) != 0) {
    printf("[%s:%d]: gets %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_LEDGER_IDX);
    goto end;
  }

end:
  return ret;
}

int deser_get_output(char const *const j_str, res_output_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    cJSON_Delete(json_obj);
    return 0;
  }
  cJSON_Delete(json_obj);

  res->u.data = get_output_new();
  if (res->u.data == NULL) {
    printf("[%s:%d]: allocate data failed\n", __func__, __LINE__);
    return -1;
  }

  return parse_get_output(j_str, res->u.data);
}

int deser_get_output_meta(char const *const j_str, res_output_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    cJSON_Delete(json_obj);
    return 0;
  }

  res->u.data = get_output_new();
  if (res->u.data == NULL) {
    printf("[%s:%d]: allocate data failed\n", __func__, __LINE__);
    return -1;
  }

  int result = parse_get_output_meta(json_obj, res->u.data);
  cJSON_Delete(json_obj);

  return result;
}

void print_get_output(get_output_t *res, uint8_t indentation) {
  printf("%s{\n", PRINT_INDENTATION(indentation));
  printf("%s\tMetadata: {\n", PRINT_INDENTATION(indentation));
  printf("%s\t\tBlock ID: ", PRINT_INDENTATION(indentation));
  dump_hex_str(res->meta.blk_id, IOTA_BLOCK_ID_BYTES);
  printf("%s\t\tTransaction ID: ", PRINT_INDENTATION(indentation));
  dump_hex_str(res->meta.tx_id, IOTA_TRANSACTION_ID_BYTES);
  printf("%s\t\tOutput Index: %" PRIu16 "\n", PRINT_INDENTATION(indentation), res->meta.output_index);
  printf("%s\t\tIs Spent: %s\n", PRINT_INDENTATION(indentation), res->meta.is_spent ? "True" : "False");
  if (res->meta.is_spent == true) {
    printf("%s\t\tMilestone Index Spent: %d\n", PRINT_INDENTATION(indentation), res->meta.ml_index_spent);
    printf("%s\t\tMilestone Timestamp Spent: %d\n", PRINT_INDENTATION(indentation), res->meta.ml_time_spent);
    printf("%s\t\tTransaction ID Spent: ", PRINT_INDENTATION(indentation));
    dump_hex_str(res->meta.tx_id_spent, IOTA_TRANSACTION_ID_BYTES);
  }
  printf("%s\t\tMilestone Index Booked: %d\n", PRINT_INDENTATION(indentation), res->meta.ml_index_booked);
  printf("%s\t\tMilestone Timestamp Booked: %d\n", PRINT_INDENTATION(indentation), res->meta.ml_time_booked);
  printf("%s\t\tLedger Index: %d\n", PRINT_INDENTATION(indentation), res->meta.ledger_index);
  printf("%s\t}\n", PRINT_INDENTATION(indentation));
  if (res->output) {
    switch (res->output->output_type) {
      case OUTPUT_BASIC:
        output_basic_print((output_basic_t *)res->output->output, indentation + 1);
        break;
      case OUTPUT_ALIAS:
        output_alias_print((output_alias_t *)res->output->output, indentation + 1);
        break;
      case OUTPUT_FOUNDRY:
        output_foundry_print((output_foundry_t *)res->output->output, indentation + 1);
        break;
      case OUTPUT_NFT:
        output_nft_print((output_nft_t *)res->output->output, indentation + 1);
        break;
      default:
        break;
    }
  }
  printf("%s}\n", PRINT_INDENTATION(indentation));
}

void dump_get_output_response(res_output_t *res, uint8_t indentation) {
  if (!res) {
    return;
  }
  if (res->is_error) {
    printf("%s\tError: %s\n", PRINT_INDENTATION(indentation), res->u.error->msg);
  } else {
    print_get_output(res->u.data, indentation);
  }
}
