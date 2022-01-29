// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/common.h"

int json_parser_common_address_deserialize(cJSON *json_obj, address_t *address) {
  if (json_obj == NULL || address == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address array
  cJSON *json_address_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_ADDR);
  if (!json_address_obj) {
    return -1;
  }

  // type
  uint8_t address_type;
  if (json_get_uint8(json_address_obj, JSON_KEY_TYPE, &address_type) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
    return -1;
  }

  // address
  switch (address_type) {
    case ADDRESS_TYPE_ED25519: {
      char address_hex[ADDRESS_ED25519_HEX_BYTES];
      if (json_get_string(json_address_obj, JSON_KEY_ADDR, address_hex, ADDRESS_ED25519_HEX_BYTES) != JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_ADDR);
        return -1;
      }
      address->type = ADDRESS_TYPE_ED25519;
      if (hex_2_bin(address_hex, ADDRESS_ED25519_HEX_BYTES, address->address, ADDRESS_ED25519_BYTES) != 0) {
        printf("[%s:%d] can not convert hex to bin number\n", __func__, __LINE__);
        return -1;
      }
      return 0;
    }
    case ADDRESS_TYPE_ALIAS:
      // TODO support alias address type
      break;
    case ADDRESS_TYPE_NFT:
      // TODO support NFT address type
      break;
    default:
      printf("[%s:%d] unsupported address type\n", __func__, __LINE__);
      return -1;
  }

  return -1;
}
