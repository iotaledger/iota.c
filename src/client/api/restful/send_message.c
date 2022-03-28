// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/json_parser/message.h"
#include "client/api/restful/get_tips.h"
#include "client/api/restful/send_message.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

char const* const cmd_msg = "/api/v2/messages";

int deser_send_message_response(char const* json_str, res_send_message_t* res) {
  int ret = -1;

  // {"messageId":"0x322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5"}
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

  // message ID
  if ((ret = json_get_string_with_prefix(json_obj, JSON_KEY_MSG_ID, res->u.msg_id, sizeof(res->u.msg_id))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
    ret = -1;
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int send_core_message(iota_client_conf_t const* const conf, core_message_t* msg, res_send_message_t* res) {
  int ret = -1;
  long http_st_code = 0;
  if (conf == NULL || msg == NULL || res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  byte_buf_t* json_data = byte_buf_new();
  byte_buf_t* node_res = byte_buf_new();
  res_tips_t* tips = NULL;
  byte_t tmp_msg_parent[IOTA_MESSAGE_ID_BYTES] = {};

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
    if (memcmp(*p, "0x", JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
      printf("[%s:%d] hex string without 0x prefix \n", __func__, __LINE__);
      ret = -1;
      goto end;
    }
    if (hex_2_bin(*p, BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES) + JSON_HEX_ENCODED_STR_PREFIX_LEN, "0x", tmp_msg_parent,
                  sizeof(tmp_msg_parent)) != 0) {
      printf("[%s:%d] converting hex to binary failed\n", __func__, __LINE__);
      ret = -1;
      goto end;
    }
    utarray_push_back(msg->parents, tmp_msg_parent);
  }

  // Serialize message object to json messsage
  cJSON* msg_json = json_message_serialize(msg);
  if (msg_json == NULL) {
    printf("[%s:%d] message json serialization failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // json object to json string
  char* msg_str = cJSON_PrintUnformatted(msg_json);
  if (msg_str == NULL) {
    printf("[%s:%d] convert to string failed\n", __func__, __LINE__);
    cJSON_Delete(msg_json);
    ret = -1;
    goto end;
  }
  cJSON_Delete(msg_json);

  // put json string into byte_buf_t
  json_data->data = (byte_t*)msg_str;
  json_data->cap = json_data->len = strlen(msg_str) + 1;

  // config http client
  http_client_config_t http_conf = {.host = conf->host, .path = cmd_msg, .use_tls = conf->use_tls, .port = conf->port};

  if ((ret = http_client_post(&http_conf, json_data, node_res, &http_st_code)) == 0) {
    // deserialize node response
    byte_buf2str(node_res);
    ret = deser_send_message_response((char const*)node_res->data, res);
  } else {
    printf("[%s:%d]: http client post failed\n", __func__, __LINE__);
  }

end:
  byte_buf_free(json_data);
  byte_buf_free(node_res);
  res_tips_free(tips);
  return ret;
}
