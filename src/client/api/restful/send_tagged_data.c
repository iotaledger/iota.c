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
    ret = -1;
    goto end;
  }

  if (tips->is_error) {
    printf("[%s:%d] get tips failed: %s\n", __func__, __LINE__, tips->u.error->msg);
    ret = -1;
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
  cJSON* parents = NULL;

  // create message object
  if ((msg_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }

  // Add NULL network id
  if (!cJSON_AddNullToObject(msg_obj, JSON_KEY_NET_ID)) {
    printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    ret = -1;
    goto end;
  }

  // add parents
  if ((parents = cJSON_CreateArray()) == NULL) {
    printf("[%s:%d] creating parent array failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    ret = -1;
    goto end;
  }

  char tmp_id_str[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)] = {};
  if (!cJSON_AddItemToObject(msg_obj, JSON_KEY_PARENT_IDS, parents)) {
    printf("[%s:%d] adding parent array failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    ret = -1;
    goto end;
  }
  byte_t* p = NULL;
  while ((p = (byte_t*)utarray_next(tips->u.tips, p))) {
    bin_2_hex(p, IOTA_MESSAGE_ID_BYTES, tmp_id_str, sizeof(tmp_id_str));
    if (!cJSON_AddItemToArray(parents, cJSON_CreateString(tmp_id_str))) {
      printf("[%s:%d] adding id to parent array failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      ret = -1;
      goto end;
    }
  }

  if (!cJSON_AddNullToObject(msg_obj, JSON_KEY_NONCE)) {
    printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    ret = -1;
    goto end;
  }

  printf("%s", cJSON_Print(msg_obj));

  ret = 0;

end:
  cJSON_Delete(msg_obj);
  res_tips_free(tips);
  return ret;
}
