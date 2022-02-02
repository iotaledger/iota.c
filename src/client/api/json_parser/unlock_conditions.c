// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/unlock_conditions.h"
#include "client/api/json_parser/common.h"
#include "core/models/outputs/unlock_conditions.h"

/*
  "type": 0,
  "address": {
    "type": 0,
    "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_cond_blk_addr_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_blk_t *unlock_blk = cond_blk_addr_new(&address);
  if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    cond_blk_free(unlock_blk);
    return -1;
  }
  cond_blk_free(unlock_blk);

  return 0;
}

/*
  "type": 1,
  "returnAddress": {
    "type": 0,
    "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  },
  "amount": 123456
*/
int json_cond_blk_dust_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // return address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, JSON_KEY_RETURN_ADDR, &address) != 0) {
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
  if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    cond_blk_free(unlock_blk);
    return -1;
  }
  cond_blk_free(unlock_blk);

  return 0;
}

/*
  "type": 2,
  "milestoneIndex": 45598,
  "unixTime": 123123
*/
int json_cond_blk_timelock_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // milestone index
  uint32_t milestone;
  if (json_get_uint32(unlock_cond_obj, JSON_KEY_MILESTONE_IDX, &milestone) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_MILESTONE_IDX);
    return -1;
  }

  // unix time
  uint32_t timestamp;
  if (json_get_uint32(unlock_cond_obj, JSON_KEY_UNIXTIME, &timestamp) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_blk_t *unlock_blk = cond_blk_timelock_new(milestone, timestamp);
  if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    cond_blk_free(unlock_blk);
    return -1;
  }
  cond_blk_free(unlock_blk);

  return 0;
}

/*
  "type": 3,
  "returnAddress": {
    "type": 0,
    "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  },
  "milestoneIndex": 45598,
  "unixTime": 123123
*/
int json_cond_blk_expir_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // return address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, JSON_KEY_RETURN_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // milestone index
  uint32_t milestone;
  if (json_get_uint32(unlock_cond_obj, JSON_KEY_MILESTONE_IDX, &milestone) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_MILESTONE_IDX);
    return -1;
  }

  // unix time
  uint32_t timestamp;
  if (json_get_uint32(unlock_cond_obj, JSON_KEY_UNIXTIME, &timestamp) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_blk_t *unlock_blk = cond_blk_expir_new(&address, milestone, timestamp);
  if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    cond_blk_free(unlock_blk);
    return -1;
  }
  cond_blk_free(unlock_blk);

  return 0;
}

/*
  "type": 4,
  "address": {
    "type": 0,
    "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_cond_blk_state_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_blk_t *unlock_blk = cond_blk_state_new(&address);
  if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    cond_blk_free(unlock_blk);
    return -1;
  }
  cond_blk_free(unlock_blk);

  return 0;
}

/*
  "type": 5,
  "address": {
    "type": 0,
    "address": "194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_cond_blk_governor_deserialize(cJSON *unlock_cond_obj, cond_blk_list_t **blk_list) {
  if (unlock_cond_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_blk_t *unlock_blk = cond_blk_governor_new(&address);
  if (cond_blk_list_add(blk_list, unlock_blk) != 0) {
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
int json_cond_blk_list_deserialize(cJSON *output_obj, cond_blk_list_t **blk_list) {
  if (output_obj == NULL || blk_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // unlockBlocks array
  cJSON *unlock_conditions_obj = cJSON_GetObjectItemCaseSensitive(output_obj, JSON_KEY_UNLOCK_CONDITIONS);
  if (!cJSON_IsArray(unlock_conditions_obj)) {
    printf("[%s:%d]: %s is not an array object\n", __func__, __LINE__, JSON_KEY_UNLOCK_CONDITIONS);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, unlock_conditions_obj) {
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
        if (json_cond_blk_timelock_deserialize(elm, blk_list) != 0) {
          printf("[%s:%d] parsing timelock unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_EXPIRATION:
        if (json_cond_blk_expir_deserialize(elm, blk_list) != 0) {
          printf("[%s:%d] parsing expiration unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_STATE:
        if (json_cond_blk_state_deserialize(elm, blk_list) != 0) {
          printf("[%s:%d] parsing state controller address unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_GOVERNOR:
        if (json_cond_blk_governor_deserialize(elm, blk_list) != 0) {
          printf("[%s:%d] parsing governor address unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      default:
        printf("[%s:%d] unsupported unlock condition\n", __func__, __LINE__);
        return -1;
    }
  }

  return 0;
}
