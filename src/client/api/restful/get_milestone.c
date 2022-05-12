// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_keys.h"
#include "client/api/json_parser/json_utils.h"
#include "client/api/json_parser/payloads/payloads.h"
#include "client/api/restful/get_milestone.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"
#include "utlist.h"

res_milestone_t *res_milestone_new() {
  res_milestone_t *ms = malloc(sizeof(res_milestone_t));
  if (ms) {
    ms->is_error = false;
    ms->u.ms = NULL;
    return ms;
  }
  return NULL;
}

void res_milestone_free(res_milestone_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.ms) {
        milestone_payload_free(res->u.ms);
      }
    }
    free(res);
  }
}

int deser_get_milestone(char const *const j_str, res_milestone_t *res) {
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

  // allocate milestone object
  res->u.ms = milestone_payload_new();
  if (!res->u.ms) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  // deserialize milestone object
  if ((ret = milestone_deserialize(json_obj, res->u.ms)) != 0) {
    printf("[%s:%d]: deserialize milestone error\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int get_milestone_by_id(iota_client_conf_t const *conf, char const ms_id[], res_milestone_t *res) {
  if (conf == NULL || ms_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(ms_id) != BIN_TO_HEX_BYTES(CRYPTO_BLAKE2B_256_HASH_BYTES)) {
    // invalid milestone id length
    printf("[%s:%d]: invalid milestone id length: %zu\n", __func__, __LINE__, strlen(ms_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str = "/milestones/0x";

  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_str) + BIN_TO_HEX_BYTES(CRYPTO_BLAKE2B_256_HASH_BYTES) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s", NODE_API_PATH, cmd_str, ms_id);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  int ret = -1;

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long st = 0;
  ret = http_client_get(&http_conf, http_res, &st);
  if (ret == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_milestone((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

int get_milestone_by_index(iota_client_conf_t const *conf, uint32_t index, res_milestone_t *res) {
  if (conf == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str = "/milestones/by-index/";

  // reserver buffer enough for cmd_str + index(max str len needed to store a unit32_t value) + null character
  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_str) + 10 + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%u", NODE_API_PATH, cmd_str, index);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  int ret = -1;

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long st = 0;
  ret = http_client_get(&http_conf, http_res, &st);
  if (ret == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_milestone((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

utxo_changes_t *utxo_changes_new() {
  utxo_changes_t *utxo_changes = malloc(sizeof(utxo_changes_t));
  if (utxo_changes) {
    utxo_changes->index = 0;
    utarray_new(utxo_changes->consumedOutputs, &ut_str_icd);
    utarray_new(utxo_changes->createdOutputs, &ut_str_icd);
    return utxo_changes;
  }
  return NULL;
}

void utxo_changes_free(utxo_changes_t *utxo_changes) {
  if (utxo_changes) {
    if (utxo_changes->consumedOutputs) {
      utarray_free(utxo_changes->consumedOutputs);
    }
    if (utxo_changes->createdOutputs) {
      utarray_free(utxo_changes->createdOutputs);
    }
    free(utxo_changes);
  }
}

int utxo_changes_deserialize(cJSON *json_obj, utxo_changes_t *res) {
  if (json_obj == NULL || res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  // parsing index
  if ((ret = json_get_uint32(json_obj, JSON_KEY_INDEX, &res->index)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_INDEX);
    return ret;
  }

  // createdOutputs
  if ((ret = json_string_with_prefix_array_to_utarray(json_obj, JSON_KEY_CREATED_OUTPUTS, res->createdOutputs)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_CREATED_OUTPUTS);
    return ret;
  }

  // consumedOutputs
  if ((ret = json_string_with_prefix_array_to_utarray(json_obj, JSON_KEY_CONSUMED_OUTPUTS, res->consumedOutputs)) !=
      0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_CONSUMED_OUTPUTS);
    return ret;
  }

  return ret;
}

res_utxo_changes_t *res_utxo_changes_new() {
  res_utxo_changes_t *utxo_changes = malloc(sizeof(res_utxo_changes_t));
  if (utxo_changes) {
    utxo_changes->is_error = false;
    utxo_changes->u.utxo_changes = NULL;
    return utxo_changes;
  }
  return NULL;
}

void res_utxo_changes_free(res_utxo_changes_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.utxo_changes) {
        utxo_changes_free(res->u.utxo_changes);
      }
    }
    free(res);
  }
}

int deser_get_utxo_changes(char const *const j_str, res_utxo_changes_t *res) {
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

  // allocate utxo_changes object
  res->u.utxo_changes = utxo_changes_new();
  if (!res->u.utxo_changes) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  // deserialize utxo_changes object
  if ((ret = utxo_changes_deserialize(json_obj, res->u.utxo_changes)) != 0) {
    printf("[%s:%d]: deserialize utxo-changes error\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

char *res_created_output_by_index(res_utxo_changes_t *res, size_t index) {
  if (res == NULL) {
    return NULL;
  }

  if (utarray_len(res->u.utxo_changes->createdOutputs)) {
    char **p = (char **)utarray_eltptr(res->u.utxo_changes->createdOutputs, index);
    return *p;
  }
  return NULL;
}

int get_utxo_changes_by_ms_id(iota_client_conf_t const *conf, char const ms_id[], res_utxo_changes_t *res) {
  if (conf == NULL || ms_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(ms_id) != BIN_TO_HEX_BYTES(CRYPTO_BLAKE2B_256_HASH_BYTES)) {
    // invalid milestone id length
    printf("[%s:%d]: invalid milestone id length: %zu\n", __func__, __LINE__, strlen(ms_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str_pre = "/milestones/0x";
  char const *const cmd_str_post = "/utxo-changes";

  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_str_pre) + BIN_TO_HEX_BYTES(CRYPTO_BLAKE2B_256_HASH_BYTES) +
                         strlen(cmd_str_post) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s%s", NODE_API_PATH, cmd_str_pre, ms_id, cmd_str_post);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  int ret = -1;

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long st = 0;
  ret = http_client_get(&http_conf, http_res, &st);
  if (ret == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_utxo_changes((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

int get_utxo_changes_by_ms_index(iota_client_conf_t const *conf, uint32_t index, res_utxo_changes_t *res) {
  if (conf == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str_pre = "/milestones/by-index/";
  char const *const cmd_str_post = "/utxo-changes";

  // reserver buffer enough for NODE_API_PATH + cmd_str_pre + index(max str len needed to store a unit32_t value) +
  // cmd_str_post + null character
  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_str_pre) + 10 + strlen(cmd_str_post) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%u%s", cmd_str_pre, index, cmd_str_post);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  int ret = -1;

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long st = 0;
  ret = http_client_get(&http_conf, http_res, &st);
  if (ret == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_utxo_changes((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

void print_utxo_changes(res_utxo_changes_t *res, uint8_t indentation) {
  if (res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }
  if (res->is_error) {
    printf("Error: %s\n", res->u.error->msg);
  } else {
    utxo_changes_t *utxo_changes = res->u.utxo_changes;
    printf("%s{\n", PRINT_INDENTATION(indentation));
    printf("%s\tIndex: %u\n", PRINT_INDENTATION(indentation), utxo_changes->index);
    int len = utarray_len(utxo_changes->createdOutputs);
    if (len > 0) {
      printf("%s\tcreatedOutputs: [\n", PRINT_INDENTATION(indentation));
      for (int i = 0; i < len; i++) {
        printf(i > 0 ? ",\n" : "");
        printf("%s\t\t%s", PRINT_INDENTATION(indentation),
               *(char **)utarray_eltptr(utxo_changes->createdOutputs, (unsigned int)i));
      }
      printf("\n");
      printf("%s\t]\n", PRINT_INDENTATION(indentation));
    } else {
      printf("%s\tcreatedOutputs: []\n", PRINT_INDENTATION(indentation));
    }
    len = utarray_len(utxo_changes->consumedOutputs);
    if (len > 0) {
      printf("%s\tconsumedOutputs: [\n", PRINT_INDENTATION(indentation));
      for (int i = 0; i < len; i++) {
        printf(i > 0 ? ",\n" : "");
        printf("%s\t\t%s", PRINT_INDENTATION(indentation),
               *(char **)utarray_eltptr(utxo_changes->consumedOutputs, (unsigned int)i));
      }
      printf("\n");
      printf("%s\t]\n", PRINT_INDENTATION(indentation));
    } else {
      printf("%s\tconsumedOutputs: []\n", PRINT_INDENTATION(indentation));
    }
    printf("%s}\n", PRINT_INDENTATION(indentation));
  }
}
