// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/unlock_conditions.h"
#include "client/api/json_parser/common.h"
#include "core/models/outputs/unlock_conditions.h"

/*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  }
*/
int json_cond_blk_addr_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_blk_t *unlock_blk = cond_blk_addr_new(&address);
  if (cond_blk_list_add(&blk_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

/*
  "address": {
    "type": 0,
    "address": "ad32258255e7cf927a4833f457f220b7187cf975e82aeee2e23fcae5056ab5f4"
  },
  "amount": 123123
*/
int json_cond_blk_dust_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t *blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // amount
  uint64_t amount;
  if (json_get_uint64(unlock_cond_obj, JSON_KEY_AMOUNT, &amount) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint64 failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_blk_t *unlock_blk = cond_blk_dust_new(&address, amount);
  if (cond_blk_list_add(&blk_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    cond_blk_free(unlock_blk);
    return -1;
  }
  cond_blk_free(unlock_blk);

  return 0;
}

/*
  "unlockConditions": [],
*/
int json_cond_blk_list_deserialize(cJSON *output_obj, cond_blk_list_t *blk_list) {
  if (output_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // unlockBlocks array
  cJSON *tx_unlock_conditions_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_UNLOCK_CONDITIONS);
  if (!cJSON_IsArray(tx_unlock_conditions_obj)) {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, tx_unlock_conditions_obj) {
    // type
    uint8_t unlock_cond_type;
    if (json_get_uint8(elm, JSON_KEY_TYPE, &unlock_cond_type) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // unlock block
    switch (unlock_cond_type) {
      case UNLOCK_COND_ADDRESS:
        if (json_cond_blk_addr_deserialize(elm, blk_list) != 0) {
          printf("[%s:%d] parsing address unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_DUST:
        if (json_cond_blk_dust_deserialize(elm, blk_list) != 0) {
          printf("[%s:%d] parsing dust deposit return unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_TIMELOCK:
        // TODO support timelock unlock condition
        break;
      case UNLOCK_COND_EXPIRATION:
        // TODO support expiration unlock condition
        break;
      case UNLOCK_COND_STATE:
        // TODO support state controller unlock condition
        break;
      case UNLOCK_COND_GOVERNOR:
        // TODO support governor controller unlock condition
        break;
      default:
        printf("[%s:%d] unsupported unlock condition\n", __func__, __LINE__);
        return -1;
    }
  }

  return 0;
}
