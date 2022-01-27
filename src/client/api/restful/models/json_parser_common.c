// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/models/json_parser_common.h"

int json_parser_common_address_deserialize(cJSON *json_obj, address_t *address) {
  if (json_obj == NULL || address == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_address_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_ADDR);
  if (!json_address_obj) {
    return -1;
  }

  cJSON *address_type = cJSON_GetObjectItemCaseSensitive(json_address_obj, JSON_KEY_TYPE);
  if (cJSON_IsNumber(address_type)) {
    if (address_type->valueint == ADDRESS_TYPE_ED25519) {
      cJSON *address_obj = cJSON_GetObjectItemCaseSensitive(json_address_obj, JSON_KEY_ADDR);
      if (cJSON_IsString(address_obj)) {
        address->type = ADDRESS_TYPE_ED25519;
        if (hex_2_bin(address_obj->valuestring, ADDRESS_ED25519_HEX_BYTES, address->address, ADDRESS_ED25519_BYTES) !=
            0) {
          printf("[%s:%d] can not convert hex to bin number\n", __func__, __LINE__);
          free(address);
          return -1;
        }
        return 0;
      }
    }
  }

  return -1;
}
