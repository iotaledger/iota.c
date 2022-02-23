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
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    goto end;
  }

  // Add type to payload
  if (!cJSON_AddNumberToObject(msg_obj, JSON_KEY_TYPE, CORE_MESSAGE_PAYLOAD_TAGGED)) {
    printf("[%s:%d] adding type to payload failed\n", __func__, __LINE__);
    goto end;
  }

  printf("%s\n", cJSON_Print(msg_obj));

  ret = 0;

end:
  cJSON_Delete(msg_obj);
  res_tips_free(tips);
  return ret;
}
