// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_parser/message.h"
#include "client/api/restful/get_message.h"
#include "client/constants.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

res_block_t *res_block_new() {
  res_block_t *blk = malloc(sizeof(res_block_t));
  if (blk) {
    blk->is_error = false;
    blk->u.blk = NULL;
    return blk;
  }
  return NULL;
}

void res_block_free(res_block_t *blk) {
  if (blk) {
    if (blk->is_error) {
      res_err_free(blk->u.error);
    } else {
      if (blk->u.blk) {
        core_block_free(blk->u.blk);
      }
    }
    free(blk);
  }
}

int deser_get_block(char const *const j_str, res_block_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    printf("[%s:%d]: parsing JSON block failed\n", __func__, __LINE__);
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

  // allocate block object
  res->u.blk = core_block_new(0);
  if (!res->u.blk) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  // deserialize a block object
  if ((ret = json_block_deserialize(json_obj, res->u.blk)) != 0) {
    printf("[%s:%d]: deserialize block error\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);

  return ret;
}

int get_block_by_id(iota_client_conf_t const *conf, char const blk_id[], res_block_t *res) {
  if (conf == NULL || blk_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(blk_id) != BIN_TO_HEX_BYTES(IOTA_BLOCK_ID_BYTES)) {
    // invalid block id length
    printf("[%s:%d]: invalid block id length: %zu\n", __func__, __LINE__, strlen(blk_id));
    return -1;
  }

  iota_str_t *cmd = NULL;
  char const *const cmd_str = "/blocks/0x";

  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_str) + BIN_TO_HEX_BYTES(IOTA_BLOCK_ID_BYTES) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s", NODE_API_PATH, cmd_str, blk_id);
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
    ret = deser_get_block((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}
