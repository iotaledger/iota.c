// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/block.h"
#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_tips.h"
#include "client/api/restful/send_block.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

int deser_send_block_response(char const* json_str, res_send_block_t* res) {
  int ret = -1;

  // {"blockId":"0x322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5"}
  cJSON* json_obj = cJSON_Parse(json_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t* res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    ret = 0;
    goto end;
  }

  // block ID
  if ((ret = json_get_string_with_prefix(json_obj, JSON_KEY_BLOCK_ID, res->u.blk_id, sizeof(res->u.blk_id))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_BLOCK_ID);
    ret = -1;
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int send_core_block(iota_client_conf_t const* const conf, core_block_t* blk, res_send_block_t* res) {
  int ret = -1;
  long http_st_code = 0;
  if (conf == NULL || blk == NULL || res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  byte_buf_t* json_data = byte_buf_new();
  byte_buf_t* node_res = byte_buf_new();
  res_tips_t* tips = NULL;
  byte_t tmp_blk_parent[IOTA_BLOCK_ID_BYTES] = {};

  if (!json_data || !node_res) {
    printf("[%s:%d] allocate http buffer failed\n", __func__, __LINE__);
    goto end;
  }

  if ((tips = res_tips_new()) == NULL) {
    printf("[%s:%d] allocate tips response failed\n", __func__, __LINE__);
    goto end;
  }

  // get tips
  if ((ret = get_tips(conf, tips)) != 0) {
    printf("[%s:%d] get tips failed\n", __func__, __LINE__);
    goto end;
  }

  if (tips->is_error) {
    printf("[%s:%d] get tips failed: %s\n", __func__, __LINE__, tips->u.error->msg);
    ret = -1;
    goto end;
  }

  char** p = NULL;
  while ((p = (char**)utarray_next(tips->u.tips, p))) {
    if (hex_2_bin(*p, BIN_TO_HEX_BYTES(IOTA_BLOCK_ID_BYTES), NULL, tmp_blk_parent, sizeof(tmp_blk_parent)) != 0) {
      printf("[%s:%d] converting hex to binary failed\n", __func__, __LINE__);
      ret = -1;
      goto end;
    }
    utarray_push_back(blk->parents, tmp_blk_parent);
  }

  // Serialize block object to json data
  cJSON* blk_json = json_block_serialize(blk);
  if (blk_json == NULL) {
    printf("[%s:%d] block json serialization failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // json object to json string
  char* blk_str = cJSON_PrintUnformatted(blk_json);
  if (blk_str == NULL) {
    printf("[%s:%d] convert to string failed\n", __func__, __LINE__);
    cJSON_Delete(blk_json);
    ret = -1;
    goto end;
  }
  cJSON_Delete(blk_json);

  // put json string into byte_buf_t
  json_data->data = (byte_t*)blk_str;
  json_data->cap = json_data->len = strlen(blk_str) + 1;

  iota_str_t* cmd = NULL;
  char const* const cmd_str = "/blocks";
  // reserver buffer enough for NODE_API_PATH + cmd_str
  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_str) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s", NODE_API_PATH, cmd_str);
  cmd->len = strlen(cmd->buf);

  // config http client
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  if ((ret = http_client_post(&http_conf, json_data, node_res, &http_st_code)) == 0) {
    // deserialize node response
    byte_buf2str(node_res);
    ret = deser_send_block_response((char const*)node_res->data, res);
  } else {
    printf("[%s:%d]: http client post failed\n", __func__, __LINE__);
  }

  iota_str_destroy(cmd);
end:
  byte_buf_free(json_data);
  byte_buf_free(node_res);
  res_tips_free(tips);
  return ret;
}
