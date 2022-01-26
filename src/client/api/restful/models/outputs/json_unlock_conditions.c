// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/models/outputs/json_unlock_conditions.h"
#include "client/api/restful/models/json_parser_common.h"
#include "core/models/outputs/unlock_conditions.h"

/*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  }
*/
int json_cond_blk_addr_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || *blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  address_t *address = json_parser_common_address_deserialize(unlock_cond_obj);
  if (address) {
    unlock_cond_blk_t *unlock_blk = cond_blk_addr_new(address);
    if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
      printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
      free_address(address);
      return -1;
    }
    return 0;
  }
  return -1;
}

/*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  },
  "amount": 123123
*/
int json_cond_blk_dust_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || *blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  address_t *address = json_parser_common_address_deserialize(unlock_cond_obj);
  if (!address) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }
  cJSON *amount_obj = cJSON_GetObjectItemCaseSensitive(unlock_cond_obj, JSON_KEY_AMOUNT);

  if (cJSON_IsNumber(amount_obj)) {
    unlock_cond_blk_t *unlock_blk = cond_blk_dust_new(address, amount_obj->valueint);
    if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
      printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
      free_address(address);
      return -1;
    }
    return 0;
  }

  free_address(address);
  return -1;
}

/*
  "unlockConditions": [],
*/
int json_cond_blk_list_deserialize(cJSON *output_obj, cond_blk_list_t *blk_list) {
  if (output_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *tx_unlock_conditions_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_UNLOCK_CONDITIONS);

  if (cJSON_IsArray(tx_unlock_conditions_obj)) {
    cJSON *elm = NULL;
    cJSON_ArrayForEach(elm, tx_unlock_conditions_obj) {
      cJSON *unlock_condition_type_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TYPE);
      if (cJSON_IsNumber(unlock_condition_type_obj)) {
        switch (unlock_condition_type_obj->valueint) {
          case UNLOCK_COND_ADDRESS:
            if (json_cond_blk_addr_deserialize(elm, &blk_list) != 0) {
              printf("[%s:%d] parsing address unlock condition failed\n", __func__, __LINE__);
              return -1;
            }
            break;
          case UNLOCK_COND_DUST:
            if (json_cond_blk_dust_deserialize(elm, &blk_list) != 0) {
              printf("[%s:%d] parsing dust deposit return unlock condition failed\n", __func__, __LINE__);
              return -1;
            }
            break;
          case UNLOCK_COND_TIMELOCK:
            break;
          case UNLOCK_COND_EXPIRATION:
            break;
          case UNLOCK_COND_STATE:
            break;
          case UNLOCK_COND_GOVERNOR:
            break;
          default:
            break;
        }
      }
    }
  } else {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    return -1;
  }

  return 0;
}
