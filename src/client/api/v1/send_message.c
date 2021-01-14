// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_utils.h"
#include "client/api/message_builder.h"
#include "client/api/v1/get_tips.h"
#include "client/api/v1/send_message.h"
#include "core/utils/iota_str.h"

// create JSON object and put the JSON string in byte_buf_t that can send by http client.
int serialize_indexation(message_t* msg, byte_buf_t* buf) {
  int ret = -1;
  cJSON* json_root = cJSON_CreateObject();
  byte_buf_t* hex_data = NULL;
  char* json_string = NULL;
  if (!json_root) {
    printf("[%s:%d] create json root object failed\n", __func__, __LINE__);
    return -1;
  }

  /*
  { "networkId": "",
    "parent1MessageId": "7f471d9bb0985e114d78489cfbaf1fb3896931bdc03c89935bacde5b9fbc86ff",
    "parent2MessageId": "3b4354521ade76145b5616a414fa283fcdb7635ee627a42ecb2f75135e18f10f",
  */
  if (!cJSON_AddStringToObject(json_root, "networkId", "")) {
    printf("[%s:%d] networkId object failed\n", __func__, __LINE__);
    goto end;
  }

  if (!cJSON_AddStringToObject(json_root, "parent1MessageId", msg->parent1)) {
    printf("[%s:%d] parent1MessageId object failed\n", __func__, __LINE__);
    goto end;
  }

  if (!cJSON_AddStringToObject(json_root, "parent2MessageId", msg->parent2)) {
    printf("[%s:%d] parent2MessageId object failed\n", __func__, __LINE__);
    goto end;
  }

  /*
    "payload": {
      "type": 2,
      "index": "iota.c",
      "data": "48656c6c6f"
    },
  */
  cJSON* json_payload = cJSON_AddObjectToObject(json_root, "payload");
  if (json_payload) {
    payload_index_t* payload = (payload_index_t*)msg->payload;
    if (!cJSON_AddNumberToObject(json_payload, "type", 2)) {
      printf("[%s:%d] payload/type object failed\n", __func__, __LINE__);
      goto end;
    }

    if (!cJSON_AddStringToObject(json_payload, "index", (char const* const)payload->index->data)) {
      printf("[%s:%d] payload/index object failed\n", __func__, __LINE__);
      goto end;
    }

    if ((hex_data = byte_buf_str2hex(payload->data)) != NULL) {
      if (!cJSON_AddStringToObject(json_payload, "data", (char const* const)hex_data->data)) {
        printf("[%s:%d] payload/data object failed\n", __func__, __LINE__);
        goto end;
      }
    } else {
      printf("[%s:%d] payload/data serialization failed\n", __func__, __LINE__);
      goto end;
    }

    /*
    "nonce": "" }
    */
    if (!cJSON_AddStringToObject(json_root, "nonce", "")) {
      printf("[%s:%d] nonce object failed\n", __func__, __LINE__);
      goto end;
    }

    // dump json object to a string
    if ((json_string = cJSON_PrintUnformatted(json_root)) == NULL) {
      printf("[%s:%d] json string print failed\n", __func__, __LINE__);
      goto end;
    }

    if (byte_buf_append(buf, (byte_t*)json_string, strlen(json_string) + 1) == false) {
      printf("[%s:%d] append json to buffer failed\n", __func__, __LINE__);
      goto end;
    }
    ret = 0;
  }

end:
  cJSON_Delete(json_root);
  byte_buf_free(hex_data);
  if (json_string) {
    free(json_string);
  }
  return ret;
}

int deser_send_message_response(char const* json_str, res_send_message_t* res) {
  int ret = -1;
  char const* const key_data = "data";
  char const* const key_msg_id = "messageId";

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

  cJSON* data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    // message ID
    if ((ret = json_get_string(data_obj, key_msg_id, res->u.msg_id, sizeof(res->u.msg_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_msg_id);
      goto end;
    }
    ret = 0;
  } else {
    printf("[%s:%d]: %s not found failed\n", __func__, __LINE__, key_data);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int send_message(iota_client_conf_t const* const conf, message_t* msg, res_send_message_t* res) {
  int ret = -1;
  long http_st_code = 0;
  iota_str_t* cmd = NULL;
  http_client_config_t http = {0};
  byte_buf_t* json_data = byte_buf_new();
  byte_buf_t* node_res = byte_buf_new();
  if (!json_data || !node_res) {
    printf("[%s:%d] allocate http buffer failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // serialize message
  switch (msg->type) {
    case MSG_PAYLOAD_TRANSACTION:
      // TODO
      break;
    case MSG_PAYLOAD_MILESTONE:
      // TODO
      break;
    case MSG_PAYLOAD_INDEXATION:
      ret = serialize_indexation(msg, json_data);
      break;
    default:
      printf("[%s:%d] UNKNOW message payload type\n", __func__, __LINE__);
      break;
  }

  if (ret != 0) {
    goto end;
  }

  // post message
  if ((cmd = iota_str_new(conf->url)) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  if (iota_str_append(cmd, "api/v1/messages")) {
    printf("[%s:%d]: string append failed\n", __func__, __LINE__);
    goto end;
  }

  http.url = cmd->buf;
  if (conf->port) {
    http.port = conf->port;
  }

  if ((ret = http_client_post(&http, json_data, node_res, &http_st_code)) == 0) {
    // deserialize node response
    byte_buf2str(node_res);
    ret = deser_send_message_response((char const*)node_res->data, res);
  } else {
    printf("[%s:%d]: http client post failed\n", __func__, __LINE__);
  }

end:
  byte_buf_free(json_data);
  byte_buf_free(node_res);
  iota_str_destroy(cmd);
  return ret;
}

int send_indexation_msg(iota_client_conf_t const* const conf, char const index[], char const data[],
                        res_send_message_t* res) {
  int ret = -1;
  // get tips
  res_tips_t tips = {};
  message_t* msg = NULL;
  payload_index_t* idx = NULL;

  if ((ret = get_tips(conf, &tips)) != 0) {
    printf("[%s:%d] get tips message failed\n", __func__, __LINE__);
    return ret;
  }

  if (tips.is_error) {
    printf("[%s:%d] get_tips response error: %s\n", __func__, __LINE__, tips.u.error->msg);
    return -1;
  }

  if ((idx = payload_index_new()) == NULL) {
    printf("[%s:%d] allocate indexation payload failed\n", __func__, __LINE__);
    return -1;
  }

  // add data and index to indexation payload
  if (!byte_buf_append(idx->data, (byte_t const*)data, strlen(data) + 1) ||
      !byte_buf_append(idx->index, (byte_t const*)index, strlen(index) + 1)) {
    printf("[%s:%d] append data and index to payload failed\n", __func__, __LINE__);
    payload_index_free(idx);
    goto done;
  }

  if ((msg = api_message_new()) == NULL) {
    printf("[%s:%d] allocate message failed\n", __func__, __LINE__);
    goto done;
  }

  // this is an indexation payload
  msg->type = MSG_PAYLOAD_INDEXATION;
  msg->payload = idx;
  memcpy(msg->parent1, tips.u.tips.tip1, API_MSG_ID_HEX_BYTES);
  memcpy(msg->parent2, tips.u.tips.tip2, API_MSG_ID_HEX_BYTES);

  // send message to a node
  if ((ret = send_message(conf, msg, res)) != 0) {
    printf("[%s:%d] send message failed\n", __func__, __LINE__);
  }

done:
  api_message_free(msg);

  return ret;
}

int send_core_message(iota_client_conf_t const* const conf, core_message_t* msg, res_send_message_t* res) {
  int ret = -1;
  long http_st_code = 0;
  iota_str_t* cmd = NULL;
  http_client_config_t http = {0};
  byte_buf_t* json_data = byte_buf_new();
  byte_buf_t* node_res = byte_buf_new();
  res_tips_t tips = {};

  if (!json_data || !node_res) {
    printf("[%s:%d] allocate http buffer failed\n", __func__, __LINE__);
    goto end;
  }

  // get tips
  if ((ret = get_tips(conf, &tips)) != 0) {
    printf("[%s:%d] get tips failed\n", __func__, __LINE__);
    goto end;
  }

  if (tips.is_error) {
    printf("[%s:%d] get tips failed: %s\n", __func__, __LINE__, tips.u.error->msg);
    res_err_free(tips.u.error);
    goto end;
  }

  hex2bin(tips.u.tips.tip1, STR_TIP_MSG_LEN, msg->parent1, sizeof(msg->parent1));
  hex2bin(tips.u.tips.tip2, STR_TIP_MSG_LEN, msg->parent2, sizeof(msg->parent2));

  char* msg_str = message_to_json(msg);
  if (!msg_str) {
    printf("[%s:%d] build message failed\n", __func__, __LINE__);
    goto end;
  }

  // put json string into byte_buf_t
  json_data->data = (byte_t*)msg_str;
  json_data->cap = json_data->len = strlen(msg_str) + 1;

  // post message
  if ((cmd = iota_str_new(conf->url)) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto end;
  }

  if (iota_str_append(cmd, "api/v1/messages")) {
    printf("[%s:%d]: string append failed\n", __func__, __LINE__);
    goto end;
  }

  http.url = cmd->buf;
  if (conf->port) {
    http.port = conf->port;
  }

  if ((ret = http_client_post(&http, json_data, node_res, &http_st_code)) == 0) {
    // deserialize node response
    byte_buf2str(node_res);
    ret = deser_send_message_response((char const*)node_res->data, res);
  } else {
    printf("[%s:%d]: http client post failed\n", __func__, __LINE__);
  }

end:
  byte_buf_free(json_data);
  byte_buf_free(node_res);
  iota_str_destroy(cmd);
  return ret;
}
