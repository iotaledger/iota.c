// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/common.h"
#include "client/api/json_parser/message.h"
#include "client/api/json_parser/payloads.h"

// TODO, move into json utils?
static json_error_t json_string_array_to_msg_ids(cJSON const* const obj, char const key[], UT_array* ut) {
  if (obj == NULL || key == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }
  byte_t tmp_id[IOTA_MESSAGE_ID_BYTES] = {};

  char* str = NULL;
  cJSON* json_item = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_item == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsArray(json_item)) {
    cJSON* current_obj = NULL;
    cJSON_ArrayForEach(current_obj, json_item) {
      str = cJSON_GetStringValue(current_obj);
      if (!str) {
        printf("[%s:%d] encountered non-string array member\n", __func__, __LINE__);
        return JSON_ERR;
      }
      // convert ID hex string to binary
      if (hex_2_bin(str, strlen(str), tmp_id, sizeof(tmp_id)) == 0) {
        utarray_push_back(ut, &tmp_id);
      } else {
        printf("[%s:%d] convert hex string to binary error\n", __func__, __LINE__);
        return JSON_ERR;
      }
    }
  } else {
    printf("[%s:%d] %s is not an array object\n", __func__, __LINE__, key);
    return JSON_NOT_ARRAY;
  }

  return JSON_OK;
}

// json object to message object
int json_message_deserialize(cJSON* json_obj, core_message_t* msg) {
  if (!msg || !json_obj) {
    printf("[%s:%d]: invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  // network ID
  char str_buff[32];
  if ((ret = json_get_string(json_obj, JSON_KEY_NET_ID, str_buff, sizeof(str_buff))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NET_ID);
    goto end;
  }
  sscanf(str_buff, "%" SCNu64, &msg->network_id);

  // parentMessageIds
  if ((ret = json_string_array_to_msg_ids(json_obj, JSON_KEY_PARENT_IDS, msg->parents)) != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_PARENT_IDS);
    utarray_free(msg->parents);
    msg->parents = NULL;
    goto end;
  }

  // nonce
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
        msg->payload = tx_payload_new();
        ret = json_transaction_deserialize(payload, (transaction_payload_t*)msg->payload);
        break;
      case CORE_MESSAGE_PAYLOAD_MILESTONE:
        // TODO
        // ret = milestone_deserialize(payload, res);
        printf("[%s:%d]: unimplemented payload type\n", __func__, __LINE__);
        break;
      case CORE_MESSAGE_PAYLOAD_TAGGED:
        ret = json_tagged_deserialize(payload, (tagged_data_t**)(&msg->payload));
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
  "networkId": "6530425480034647824",
  "parentMessageIds": [
      "7dabd008324378d65e607975e9f1740aa8b2f624b9e25248370454dcd07027f3",
      "9f5066de0e3225f062e9ac8c285306f56815677fe5d1db0bbccecfc8f7f1e82c",
      "ccf9bf6b76a2659f332e17bfdc20f278ce25bc45e807e89cc2ab526cd2101c52",
      "fe63a9194eadb45e456a3c618d970119dbcac25221dbf5f53e5a838ef6ef518a"
  ],
  "payload": payload object
  "nonce": "2695978"
  }
  */
  cJSON* msg_obj = NULL;
  cJSON* payload = NULL;
  cJSON* parents = NULL;
  char tmp_id_str[IOTA_MESSAGE_ID_BYTES * 2 + 1] = {};

  if (!msg) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // create message object
  if ((msg_obj = cJSON_CreateObject()) == NULL) {
    printf("[%s:%d] creating message object failed\n", __func__, __LINE__);
    return NULL;
  }

  // add network ID
  if (msg->network_id > 0) {
    if (!cJSON_AddNumberToObject(msg_obj, JSON_KEY_NET_ID, msg->network_id)) {
      printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  } else {
    if (!cJSON_AddNullToObject(msg_obj, JSON_KEY_NET_ID)) {
      printf("[%s:%d] creating network ID failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
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
    bin_2_hex(p, IOTA_MESSAGE_ID_BYTES, tmp_id_str, sizeof(tmp_id_str));
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
      printf("[%s:%d] Unknow payload type\n", __func__, __LINE__);
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
    if (!cJSON_AddNumberToObject(msg_obj, JSON_KEY_NONCE, msg->nonce)) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  } else {
    if (!cJSON_AddNullToObject(msg_obj, JSON_KEY_NONCE)) {
      printf("[%s:%d] creating nonce failed\n", __func__, __LINE__);
      cJSON_Delete(msg_obj);
      return NULL;
    }
  }

  return msg_obj;
}
