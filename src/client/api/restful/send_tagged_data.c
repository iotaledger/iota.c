// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_tips.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/macros.h"

int send_tagged_data_message(iota_client_conf_t const* conf, uint8_t ver, byte_t tag[], uint8_t tag_len, byte_t data[],
                             uint32_t data_len, res_send_message_t* res) {
  int ret = -1;
  if (conf == NULL || res == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (data_len > 0 && data == NULL) {
    printf("[%s:%d] data cannot be null if data_len is greater than 0\n", __func__, __LINE__);
    return -1;
  }

  if (tag_len > 0 && tag == NULL) {
    printf("[%s:%d] tag cannot be null if tag_len is greater than 0\n", __func__, __LINE__);
    return -1;
  }

  if (tag_len > TAGGED_DATA_TAG_MAX_LENGTH_BYTES) {
    printf("[%s:%d] invalid tag\n", __func__, __LINE__);
    return -1;
  }

  res_tips_t* tips = res_tips_new();
  if (!tips) {
    printf("[%s:%d] allocate tips response failed\n", __func__, __LINE__);
    return -1;
  }

  // get tips
  if ((get_tips(conf, tips)) != 0) {
    printf("[%s:%d] get tips failed\n", __func__, __LINE__);
    res_tips_free(tips);
    return -1;
  }

  if (tips->is_error) {
    printf("[%s:%d] get tips failed: %s\n", __func__, __LINE__, tips->u.error->msg);
    res_tips_free(tips);
    return -1;
  }

  // compose json message
  /*
  {
  "protocolVersion": 2,
  "parentMessageIds": [
      "0x7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
      "0x9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
      "0xccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52",
      "0xfe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a"
  ],
  "payload": {
    "type": 5,
    "tag": "0x696f74612e63f09fa68b",
    "data": "0x48656c6c6f20576f726c64"
  }
  "nonce": ""
  }
  */

  // create message object
  cJSON* msg_obj = cJSON_CreateObject();
  if (msg_obj == NULL) {
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    goto end;
  }

  // add protocol version
  if (!cJSON_AddNumberToObject(msg_obj, JSON_KEY_PROTOCOL_VERSION, ver)) {
    printf("[%s:%d] adding protocol version failed\n", __func__, __LINE__);
    goto end;
  }

  // add parents
  if (utarray_to_json_string_array(tips->u.tips, msg_obj, JSON_KEY_PARENT_IDS) != JSON_OK) {
    printf("[%s:%d] adding tips array to message object failed\n", __func__, __LINE__);
    goto end;
  }

  // add nonce
  if (!cJSON_AddStringToObject(msg_obj, JSON_KEY_NONCE, "")) {
    printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
    goto end;
  }

  // create payload object
  cJSON* payload = cJSON_CreateObject();
  if (payload == NULL) {
    printf("[%s:%d] creating payload object failed\n", __func__, __LINE__);
    goto end;
  }

  // add payload to message
  if (!cJSON_AddItemToObject(msg_obj, JSON_KEY_PAYLOAD, payload)) {
    printf("[%s:%d] adding payload failed\n", __func__, __LINE__);
    cJSON_Delete(payload);
    goto end;
  }

  // add type to payload
  if (!cJSON_AddNumberToObject(payload, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TAGGED)) {
    printf("[%s:%d] adding type to payload failed\n", __func__, __LINE__);
    goto end;
  }

  // add tag
  char tag_str[BIN_TO_HEX_STR_BYTES(TAGGED_DATA_TAG_MAX_LENGTH_BYTES) + JSON_HEX_ENCODED_STRING_PREFIX_LEN] = {0};
  tag_str[0] = '0';
  tag_str[1] = 'x';
  if (bin_2_hex(tag, tag_len, tag_str + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                sizeof(tag_str) - JSON_HEX_ENCODED_STRING_PREFIX_LEN) != 0) {
    printf("[%s:%d] bin to hex tag conversion failed\n", __func__, __LINE__);
    goto end;
  }
  if (!cJSON_AddStringToObject(payload, JSON_KEY_TAG, tag_str)) {
    printf("[%s:%d] adding tag to payload failed\n", __func__, __LINE__);
    goto end;
  }

  // data
  if (data) {
    char* data_str = malloc(BIN_TO_HEX_STR_BYTES(data_len) + JSON_HEX_ENCODED_STRING_PREFIX_LEN);
    if (!data_str) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);

      goto end;
    }
    data_str[0] = '0';
    data_str[1] = 'x';
    if (bin_2_hex(data, data_len, data_str + JSON_HEX_ENCODED_STRING_PREFIX_LEN, BIN_TO_HEX_STR_BYTES(data_len)) != 0) {
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

  // json object to json string
  char* msg_str = cJSON_PrintUnformatted(msg_obj);
  if (msg_str == NULL) {
    printf("[%s:%d] converting json to string failed\n", __func__, __LINE__);
    goto end;
  }

  // put json string into byte_buf_t
  byte_buf_t* json_data = byte_buf_new_with_data((byte_t*)msg_str, strlen(msg_str) + 1);
  if (!json_data) {
    printf("[%s:%d] allocating buffer with message data failed\n", __func__, __LINE__);
    goto end;
  }
  // not needed anymore
  free(msg_str);
  // config http client
  http_client_config_t http_conf = {
      .host = conf->host, .path = "/api/v2/messages", .use_tls = conf->use_tls, .port = conf->port};
  long http_st_code = 0;
  byte_buf_t* http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d] allocating buffer for http response failed\n", __func__, __LINE__);
    goto end;
  }
  if ((ret = http_client_post(&http_conf, json_data, http_res, &http_st_code)) == 0) {
    // deserialize node response
    if (!byte_buf2str(http_res)) {
      byte_buf_free(json_data);
      byte_buf_free(http_res);
      printf("[%s:%d]: buffer to string conversion failed\n", __func__, __LINE__);
      goto end;
    }
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
