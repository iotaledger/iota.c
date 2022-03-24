// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/common.h"
#include "cJSON.h"
#include "core/utils/macros.h"

int json_parser_common_address_deserialize(cJSON *json_obj, char const *const json_address_key, address_t *address) {
  if (json_obj == NULL || address == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address array
  cJSON *json_address_obj = cJSON_GetObjectItemCaseSensitive(json_obj, json_address_key);
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
      if (json_get_hex_str_to_bin(json_address_obj, JSON_KEY_PUB_KEY_HASH, address->address, ED25519_PUBKEY_BYTES) !=
          JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_PUB_KEY_HASH);
        return -1;
      }
      address->type = ADDRESS_TYPE_ED25519;
      break;
    }
    case ADDRESS_TYPE_ALIAS: {
      if (json_get_hex_str_to_bin(json_address_obj, JSON_KEY_ALIAS_ID, address->address, ALIAS_ID_BYTES) != JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_ALIAS_ID);
        return -1;
      }
      address->type = ADDRESS_TYPE_ALIAS;
      break;
    }
    case ADDRESS_TYPE_NFT: {
      if (json_get_hex_str_to_bin(json_address_obj, JSON_KEY_NFT_ID, address->address, NFT_ID_BYTES) != JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_NFT_ID);
        return -1;
      }
      address->type = ADDRESS_TYPE_NFT;
      break;
    }
    default:
      printf("[%s:%d] unsupported address type\n", __func__, __LINE__);
      return -1;
  }

  return 0;
}

/*
{
  "type": 0,
  "pubKeyHash": "0x21e26b38a3308d6262ae9921f46ac871457ef6813a38f6a2e77c947b1d79c942"
}
or
{
  "type": 8,
  "aliasId": "0xa3308d6262ae9921f46aa3308d6262ae9921f46a"
}
or
{
  "type": 16,
  "nftId": "0xa3308d6262ae9921f46aa3308d6262ae9921f46a"
}
*/
cJSON *json_parser_common_address_serialize(address_t *address) {
  char addr_str[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES) + JSON_HEX_ENCODED_STRING_PREFIX_LEN] = {};
  memcpy(addr_str, "0x", JSON_HEX_ENCODED_STRING_PREFIX_LEN);

  // address data object
  cJSON *addr_data = cJSON_CreateObject();

  if (addr_data) {
    // add type to address object
    cJSON_AddNumberToObject(addr_data, JSON_KEY_TYPE, address->type);

    // convert bin address to hex string
    int ret = -1;
    switch (address->type) {
      case ADDRESS_TYPE_ED25519:
        if ((ret = bin_2_hex(address->address, ED25519_PUBKEY_BYTES, addr_str + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                             sizeof(addr_str) - JSON_HEX_ENCODED_STRING_PREFIX_LEN)) == 0) {
          cJSON_AddStringToObject(addr_data, JSON_KEY_PUB_KEY_HASH, addr_str);
        }
        break;
      case ADDRESS_TYPE_ALIAS:
        if ((ret = bin_2_hex(address->address, ALIAS_ID_BYTES, addr_str + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                             sizeof(addr_str) - JSON_HEX_ENCODED_STRING_PREFIX_LEN)) == 0) {
          cJSON_AddStringToObject(addr_data, JSON_KEY_ALIAS_ID, addr_str);
        }
        break;
      case ADDRESS_TYPE_NFT:
        if ((ret = bin_2_hex(address->address, NFT_ID_BYTES, addr_str + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                             sizeof(addr_str) - JSON_HEX_ENCODED_STRING_PREFIX_LEN)) == 0) {
          cJSON_AddStringToObject(addr_data, JSON_KEY_NFT_ID, addr_str);
        }
        break;
      default:
        printf("[%s:%d] invalid address type\n", __func__, __LINE__);
        break;
    }

    if (ret != 0) {
      printf("[%s:%d] convert address to hex string failed\n", __func__, __LINE__);
      cJSON_Delete(addr_data);
      return NULL;
    }
  }

  return addr_data;
}
