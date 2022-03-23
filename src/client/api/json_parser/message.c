// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/common.h"
#include "client/api/json_parser/message.h"
#include "client/api/json_parser/payloads/payloads.h"
#include "core/utils/macros.h"

// json object to message object
int json_message_deserialize(cJSON* json_obj, core_message_t* msg) {
  if (!msg || !json_obj) {
    printf("[%s:%d]: invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  // protocol version
  if ((ret = json_get_uint8(json_obj, JSON_KEY_PROTOCOL_VERSION, &msg->protocol_version)) != 0) {
    printf("[%s:%d]: gets %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_PROTOCOL_VERSION);
    goto end;
  }

  // parentMessageIds
  if ((ret = json_string_array_to_bin_array(json_obj, JSON_KEY_PARENT_IDS, msg->parents, IOTA_MESSAGE_ID_BYTES)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
    utarray_free(msg->parents);
    msg->parents = NULL;
    goto end;
  }

  // nonce
  char str_buff[32];
  if ((ret = json_get_string(json_obj, JSON_KEY_NONCE, str_buff, sizeof(str_buff))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NONCE);
    goto end;
  }
  sscanf(str_buff, "%" SCNu64, &msg->nonce);

  // payload
  cJSON* payload = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_PAYLOAD);
  if (payload) {
    if (json_get_uint32(payload, JSON_KEY_TYPE, &msg->payload_type) != 0) {
      printf("[%s:%d]: gets payload %s failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      goto end;
    }

    switch (msg->payload_type) {
      case CORE_MESSAGE_PAYLOAD_TRANSACTION:
        msg->payload = tx_payload_new(0);
        ret = json_transaction_deserialize(payload, (transaction_payload_t*)msg->payload);
        break;
      case CORE_MESSAGE_PAYLOAD_MILESTONE:
        msg->payload = milestone_payload_new();
        ret = milestone_deserialize(payload, (milestone_payload_t*)msg->payload);
        break;
      case CORE_MESSAGE_PAYLOAD_TAGGED:
        ret = json_tagged_deserialize(payload, (tagged_data_payload_t**)(&msg->payload));
        break;
      case CORE_MESSAGE_PAYLOAD_INDEXATION:
      case CORE_MESSAGE_PAYLOAD_RECEIPT:
      case CORE_MESSAGE_PAYLOAD_TREASURY:
        printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
        ret = -1;
        break;
      default:
        // do nothing
        break;
    }

  } else {
    printf("[%s:%d]: invalid message: payload not found\n", __func__, __LINE__);
    ret = -1;
  }

end:

  return ret;
}

// message object to JSON object
cJSON* json_message_serialize(core_message_t* msg) {
  /*
  {
  "protocolVersion": 2,
  "parentMessageIds": [
      "0x7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
      "0x9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
      "0xccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52",
      "0xfe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a"
  ],
  "payload": payload object
  "nonce": "2695978"
  }
  */
  cJSON* msg_obj = NULL;
  cJSON* payload = NULL;
  cJSON* parents = NULL;
  char tmp_id_str[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES) + JSON_HEX_ENCODED_STRING_PREFIX_LEN] = {};

  if (!msg) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create message object
  if ((msg_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    return NULL;
  }

  // add protocol version
  if (!cJSON_AddNumberToObject(msg_obj, JSON_KEY_PROTOCOL_VERSION, msg->protocol_version)) {
    printf("[%s:%d] creating protocol version failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }

  // add parents
  if ((parents = cJSON_CreateArray()) == NULL) {
    printf("[%s:%d] creating parent array failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }

  cJSON_AddItemToObject(msg_obj, JSON_KEY_PARENT_IDS, parents);
  byte_t* p = NULL;
  while ((p = (byte_t*)utarray_next(msg->parents, p))) {
    tmp_id_str[0] = '0';
    tmp_id_str[1] = 'x';
    bin_2_hex(p, IOTA_MESSAGE_ID_BYTES, tmp_id_str + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
              sizeof(tmp_id_str) - JSON_HEX_ENCODED_STRING_PREFIX_LEN);
    cJSON_AddItemToArray(parents, cJSON_CreateString(tmp_id_str));
  }

  // add payload
  switch (msg->payload_type) {
    case CORE_MESSAGE_PAYLOAD_TRANSACTION:
      payload = json_transaction_serialize((transaction_payload_t*)msg->payload);
      break;
    case CORE_MESSAGE_PAYLOAD_MILESTONE:
    case CORE_MESSAGE_PAYLOAD_INDEXATION:
    case CORE_MESSAGE_PAYLOAD_RECEIPT:
    case CORE_MESSAGE_PAYLOAD_TREASURY:
      printf("[%s:%d] unsupported payload type\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    case CORE_MESSAGE_PAYLOAD_TAGGED:
      payload = json_tagged_serialize((void*)msg->payload);
      break;
    default:
      printf("[%s:%d] Unknown payload type\n", __func__, __LINE__);
      break;
  }

  if (payload == NULL) {
    printf("[%s:%d] creating payload failed\n", __func__, __LINE__);
    cJSON_Delete(msg_obj);
    return NULL;
  }
  cJSON_AddItemToObject(msg_obj, JSON_KEY_PAYLOAD, payload);

  // add nonce
  if (msg->nonce > 0) {
    char nonce_buff[65] = {};
    sprintf(nonce_buff, "%" PRIu64 "", msg->nonce);
    if (!cJSON_AddStringToObject(msg_obj, JSON_KEY_NONCE, nonce_buff)) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  } else {
    if (!cJSON_AddStringToObject(msg_obj, JSON_KEY_NONCE, "")) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  }

  return msg_obj;
}
