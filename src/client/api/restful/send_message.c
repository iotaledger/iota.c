// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/message_builder.h"
#include "client/api/restful/get_tips.h"
#include "client/api/restful/send_message.h"
#include "core/utils/iota_str.h"

char const* const cmd_msg = "/api/v1/messages";

int deser_send_message_response(char const* json_str, res_send_message_t* res) {
  int ret = -1;

  // {"data":{"messageId":"322a02c8b4e7b5090b45f967f29a773dfa1dbd0302f7b9bfa253db55316581e5"}}
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

  cJSON* data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_DATA);
  if (data_obj) {
    // message ID
    if ((ret = json_get_string(data_obj, JSON_KEY_MSG_ID, res->u.msg_id, sizeof(res->u.msg_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_MSG_ID);
      goto end;
    }
    ret = 0;
  } else {
    printf("[%s:%d]: %s not found failed\n", __func__, __LINE__, JSON_KEY_DATA);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int send_core_message(iota_client_conf_t const* const conf, core_message_t* msg, res_send_message_t* res) {
  int ret = -1;
  long http_st_code = 0;
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
    goto end;
  }

  char** p = NULL;
  while ((p = (char**)utarray_next(tips->u.tips, p))) {
    hex_2_bin(*p, IOTA_MESSAGE_ID_HEX_BYTES, tmp_msg_parent, sizeof(tmp_msg_parent));
    utarray_push_back(msg->parents, tmp_msg_parent);
  }

  char* msg_str = message_to_json(msg);
  if (!msg_str) {
    printf("[%s:%d] build message failed\n", __func__, __LINE__);
    goto end;
  }

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
