// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_tips.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/utils/macros.h"
#include "utarray.h"

int send_tagged_data_message(iota_client_conf_t const* conf, byte_t tag[], uint8_t tag_len, byte_t data[],
                             uint32_t data_len, res_send_message_t* res) {
  if (conf == NULL || tag == NULL || res == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (data_len > 0 && data == NULL) {
    printf("[%s:%d] data cannot be null if data_len is greater than 0\n", __func__, __LINE__);
    return -1;
  }

  // Max tag length allowed is 64
  if (tag_len > 64) {
    printf("[%s:%d] invalid tag\n", __func__, __LINE__);
    return -1;
  }

  res_tips_t* tips = NULL;
  if ((tips = res_tips_new()) == NULL) {
    printf("[%s:%d] allocate tips response failed\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  // get tips
  if ((get_tips(conf, tips)) != 0) {
    printf("[%s:%d] get tips failed\n", __func__, __LINE__);
    goto end;
  }

  if (tips->is_error) {
    printf("[%s:%d] get tips failed: %s\n", __func__, __LINE__, tips->u.error->msg);
    goto end;
  }

  // compose json message
  /*
  {
  "networkId": "",
  "parentMessageIds": [
      "7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
      "9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
      "ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52",
      "fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a"
  ],
  "payload": {
    "type": 5,
    "tag": "696f74612e63f09fa68b",
    "data": "48656c6c6f20576f726c64"
  }
  "nonce": ""
  }
  */
  cJSON* msg_obj = NULL;
  cJSON* payload = NULL;

  // create message object
  if ((msg_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    goto end;
  }

  // Add NULL network id
  if (!cJSON_AddNullToObject(msg_obj, JSON_KEY_NET_ID)) {
    printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
    goto end;
  }

  // add parents
  if (utarray_to_json_string_array(tips->u.tips, msg_obj, JSON_KEY_PARENT_IDS) != JSON_OK) {
    printf("[%s:%d] adding tips array to message object failed\n", __func__, __LINE__);
    goto end;
  }

  // add nonce
  if (!cJSON_AddNullToObject(msg_obj, JSON_KEY_NONCE)) {
    printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
    goto end;
  }

  // create payload object
  if ((payload = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating payload object failed\n", __func__, __LINE__);
    goto end;
  }

  // add type to payload
  if (!cJSON_AddNumberToObject(payload, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TAGGED)) {
    printf("[%s:%d] adding type to payload failed\n", __func__, __LINE__);
    goto end;
  }

  // add tag
  // max tag length is 64
  char tag_str[BIN_TO_HEX_STR_BYTES(64)] = {0};
  if (bin_2_hex(tag, tag_len, tag_str, sizeof(tag_str)) != 0) {
    printf("[%s:%d] bin to hex tag conversion failed\n", __func__, __LINE__);
    goto end;
  }
  if (!cJSON_AddStringToObject(payload, JSON_KEY_TAG, tag_str)) {
    printf("[%s:%d] adding tag to payload failed\n", __func__, __LINE__);
    goto end;
  }

  // data
  if (data) {
    char* data_str = malloc(BIN_TO_HEX_STR_BYTES(data_len));
    if (!data_str) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      goto end;
    }
    if (bin_2_hex(data, data_len, data_str, BIN_TO_HEX_STR_BYTES(data_len)) != 0) {
      printf("[%s:%d] bin to hex data conversion failed\n", __func__, __LINE__);
      free(data_str);
      goto end;
    }
    if (!cJSON_AddStringToObject(payload, JSON_KEY_DATA, data_str)) {
      printf("[%s:%d] adding tag data failed\n", __func__, __LINE__);
      free(data_str);
      goto end;
    }
    free(data_str);
  } else {
    // add a null data to tagged data
    if (!cJSON_AddNullToObject(payload, JSON_KEY_DATA)) {
      printf("[%s:%d] adding null data payload failed\n", __func__, __LINE__);
      goto end;
    }
  }

  // add payload to message
  if (!cJSON_AddItemToObject(msg_obj, JSON_KEY_PAYLOAD, payload)) {
    printf("[%s:%d] adding payload failed\n", __func__, __LINE__);
    goto end;
  }

  // json object to json string
  char* msg_str = NULL;
  if ((msg_str = cJSON_PrintUnformatted(msg_obj)) == NULL) {
    printf("[%s:%d] converting json to string failed\n", __func__, __LINE__);
    goto end;
  }

  // put json string into byte_buf_t
  byte_buf_t* json_data = byte_buf_new();
  json_data->data = (byte_t*)msg_str;
  json_data->cap = json_data->len = strlen(msg_str) + 1;

  // config http client
  http_client_config_t http_conf = {
      .host = conf->host, .path = "/api/v2/messages", .use_tls = conf->use_tls, .port = conf->port};
  long http_st_code = 0;
  byte_buf_t* http_res = byte_buf_new();
  if ((ret = http_client_post(&http_conf, json_data, http_res, &http_st_code)) == 0) {
    // deserialize node response
    byte_buf2str(http_res);
    ret = deser_send_message_response((char const*)http_res->data, res);
  } else {
    printf("[%s:%d]: http client post failed\n", __func__, __LINE__);
  }
  byte_buf_free(json_data);
  byte_buf_free(http_res);

end:
  cJSON_Delete(msg_obj);
  res_tips_free(tips);
  return ret;
}
