// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "client/api/json_parser/common.h"
#include "client/api/json_parser/outputs/unlock_conditions.h"
#include "core/models/outputs/unlock_conditions.h"
#include "utlist.h"

/*
  "type": 0,
  "address": {
    "type": 0,
    "pubKeyHash": "0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_condition_addr_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list) {
  if (unlock_cond_obj == NULL || cond_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, JSON_KEY_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // add a new unlock condition into the list
  unlock_cond_t *unlock_blk = condition_addr_new(&address);
  if (condition_list_add(cond_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    condition_free(unlock_blk);
    return -1;
  }
  condition_free(unlock_blk);

  return 0;
}

static cJSON *json_condition_addr_serialize(unlock_cond_t *cond) {
  if (!cond || cond->type != UNLOCK_COND_ADDRESS) {
    printf("[%s:%d] invalid cond\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *addr_obj = cJSON_CreateObject();
  if (addr_obj) {
    // add type to sender
    if (!cJSON_AddNumberToObject(addr_obj, JSON_KEY_TYPE, UNLOCK_COND_ADDRESS)) {
      printf("[%s:%d] add type into condition error\n", __func__, __LINE__);
      goto err;
    }

    // add address to sender
    cJSON *addr = json_parser_common_address_serialize((address_t *)cond->obj);
    if (addr) {
      if (!cJSON_AddItemToObject(addr_obj, JSON_KEY_ADDR, addr)) {
        printf("[%s:%d] add address into condition error\n", __func__, __LINE__);
        cJSON_Delete(addr);
        goto err;
      }
    } else {
      cJSON_Delete(addr_obj);
      return NULL;
    }
  }
  return addr_obj;

err:
  cJSON_Delete(addr_obj);
  return NULL;
}

/*
  "type": 1,
  "returnAddress": {
    "type": 0,
    "pubKeyHash": "0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  },
  "amount": "123456"
*/
int json_condition_storage_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list) {
  if (unlock_cond_obj == NULL || cond_list == NULL) {
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
  char str_buff[32];
  if (json_get_string(unlock_cond_obj, JSON_KEY_AMOUNT, str_buff, sizeof(str_buff)) != JSON_OK) {
    printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_AMOUNT);
    return -1;
  }
  sscanf(str_buff, "%" SCNu64, &amount);

  // add new unlock condition into a list
  unlock_cond_t *unlock_blk = condition_storage_new(&address, amount);
  if (condition_list_add(cond_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    condition_free(unlock_blk);
    return -1;
  }
  condition_free(unlock_blk);

  return 0;
}

static cJSON *json_condition_storage_serialize(unlock_cond_storage_t *storage) {
  if (!storage) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *storage_obj = cJSON_CreateObject();
  if (storage_obj) {
    // add type
    if (!cJSON_AddNumberToObject(storage_obj, JSON_KEY_TYPE, UNLOCK_COND_STORAGE)) {
      printf("[%s:%d] add type into condition error\n", __func__, __LINE__);
      goto err;
    }

    // add return address
    cJSON *addr = json_parser_common_address_serialize(storage->addr);
    if (addr) {
      if (!cJSON_AddItemToObject(storage_obj, JSON_KEY_ADDR, addr)) {
        printf("[%s:%d] add return address into condition error\n", __func__, __LINE__);
        cJSON_Delete(addr);
        goto err;
      }
    } else {
      printf("[%s:%d] create return address object error\n", __func__, __LINE__);
      goto err;
    }

    // add return amount
    if (!cJSON_AddNumberToObject(storage_obj, JSON_KEY_AMOUNT, storage->amount)) {
      printf("[%s:%d] add return amount into condition error\n", __func__, __LINE__);
      goto err;
    }
  }
  return storage_obj;

err:
  cJSON_Delete(storage_obj);
  return NULL;
}

/*
  "type": 2,
  "unixTime": 123123
*/
int json_condition_timelock_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list) {
  if (unlock_cond_obj == NULL || cond_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // unix time
  uint32_t timestamp;
  if (json_get_uint32(unlock_cond_obj, JSON_KEY_UNIXTIME, &timestamp) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_t *unlock_blk = condition_timelock_new(timestamp);
  if (condition_list_add(cond_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    condition_free(unlock_blk);
    return -1;
  }
  condition_free(unlock_blk);

  return 0;
}

static cJSON *json_condition_timelock_serialize(unlock_cond_timelock_t *timelock) {
  cJSON *time_obj = cJSON_CreateObject();
  if (time_obj) {
    // add type
    if (!cJSON_AddNumberToObject(time_obj, JSON_KEY_TYPE, UNLOCK_COND_TIMELOCK)) {
      printf("[%s:%d] add type into condition error\n", __func__, __LINE__);
      goto err;
    }
    // add Unix time
    if (!cJSON_AddNumberToObject(time_obj, JSON_KEY_UNIXTIME, timelock->time)) {
      printf("[%s:%d] add Unix time into condition error\n", __func__, __LINE__);
      goto err;
    }
  }
  return time_obj;

err:
  cJSON_Delete(time_obj);
  return NULL;
}

/*
  "type": 3,
  "returnAddress": {
    "type": 0,
    "pubKeyHash": "0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  },
  "unixTime": 123123
*/
int json_condition_expir_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list) {
  if (unlock_cond_obj == NULL || cond_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // return address
  address_t address;
  if (json_parser_common_address_deserialize(unlock_cond_obj, JSON_KEY_RETURN_ADDR, &address) != 0) {
    printf("[%s:%d] can not parse address JSON object\n", __func__, __LINE__);
    return -1;
  }

  // unix time
  uint32_t timestamp;
  if (json_get_uint32(unlock_cond_obj, JSON_KEY_UNIXTIME, &timestamp) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint32 failed\n", __func__, __LINE__, JSON_KEY_TIMESTAMP);
    return -1;
  }

  // add new unlock condition into a list
  unlock_cond_t *unlock_blk = condition_expir_new(&address, timestamp);
  if (condition_list_add(cond_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    condition_free(unlock_blk);
    return -1;
  }
  condition_free(unlock_blk);

  return 0;
}

static cJSON *json_condition_expir_serialize(unlock_cond_expir_t *expir) {
  cJSON *expir_obj = cJSON_CreateObject();
  if (expir_obj) {
    // add type
    if (!cJSON_AddNumberToObject(expir_obj, JSON_KEY_TYPE, UNLOCK_COND_EXPIRATION)) {
      printf("[%s:%d] add type into condition error\n", __func__, __LINE__);
      goto err;
    }

    // add return address
    cJSON *addr = json_parser_common_address_serialize(expir->addr);
    if (addr) {
      if (!cJSON_AddItemToObject(expir_obj, JSON_KEY_ADDR, addr)) {
        cJSON_Delete(addr);
        goto err;
      }
    } else {
      printf("[%s:%d] add return address into condition error\n", __func__, __LINE__);
      goto err;
    }

    // add Unix time
    if (!cJSON_AddNumberToObject(expir_obj, JSON_KEY_UNIXTIME, expir->time)) {
      printf("[%s:%d] add Unix time into condition error\n", __func__, __LINE__);
      goto err;
    }
  }
  return expir_obj;

err:
  cJSON_Delete(expir_obj);
  return NULL;
}

/*
  "type": 4,
  "address": {
    "type": 0,
    "pubKeyHash": "0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_condition_state_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list) {
  if (unlock_cond_obj == NULL || cond_list == NULL) {
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
  unlock_cond_t *unlock_blk = condition_state_new(&address);
  if (condition_list_add(cond_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    condition_free(unlock_blk);
    return -1;
  }
  condition_free(unlock_blk);

  return 0;
}

static cJSON *json_condition_state_serialize(unlock_cond_t *cond) {
  if (!cond || cond->type != UNLOCK_COND_STATE) {
    printf("[%s:%d] invalid condition\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *addr_obj = cJSON_CreateObject();
  if (addr_obj) {
    // add type to sender
    if (!cJSON_AddNumberToObject(addr_obj, JSON_KEY_TYPE, UNLOCK_COND_STATE)) {
      printf("[%s:%d] add type into condition error\n", __func__, __LINE__);
      goto err;
    }

    // add address to sender
    cJSON *addr = json_parser_common_address_serialize((address_t *)cond->obj);
    if (addr) {
      if (!cJSON_AddItemToObject(addr_obj, JSON_KEY_ADDR, addr)) {
        printf("[%s:%d] add address into condition error\n", __func__, __LINE__);
        cJSON_Delete(addr);
        goto err;
      }
    } else {
      cJSON_Delete(addr_obj);
      return NULL;
    }
  }
  return addr_obj;

err:
  cJSON_Delete(addr_obj);
  return NULL;
}

/*
  "type": 5,
  "address": {
    "type": 0,
    "pubKeyHash": "0x194eb32b9b6c61207192c7073562a0b3adf50a7c1f268182b552ec8999380acb"
  }
*/
int json_condition_governor_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list) {
  if (unlock_cond_obj == NULL || cond_list == NULL) {
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
  unlock_cond_t *unlock_blk = condition_governor_new(&address);
  if (condition_list_add(cond_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    condition_free(unlock_blk);
    return -1;
  }
  condition_free(unlock_blk);

  return 0;
}

static cJSON *json_condition_governor_serialize(unlock_cond_t *cond) {
  if (!cond || cond->type != UNLOCK_COND_GOVERNOR) {
    printf("[%s:%d] invalid condition\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *addr_obj = cJSON_CreateObject();
  if (addr_obj) {
    // add type to sender
    if (!cJSON_AddNumberToObject(addr_obj, JSON_KEY_TYPE, UNLOCK_COND_GOVERNOR)) {
      printf("[%s:%d] add type into condition error\n", __func__, __LINE__);
      goto err;
    }

    // add address to sender
    cJSON *addr = json_parser_common_address_serialize((address_t *)cond->obj);
    if (addr) {
      if (!cJSON_AddItemToObject(addr_obj, JSON_KEY_ADDR, addr)) {
        printf("[%s:%d] add address into condition error\n", __func__, __LINE__);
        cJSON_Delete(addr);
        goto err;
      }
    } else {
      cJSON_Delete(addr_obj);
      return NULL;
    }
  }
  return addr_obj;

err:
  cJSON_Delete(addr_obj);
  return NULL;
}

/*
  "type": 6,
  "address": {
    "type": 0,
    "aliasId": "01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248"
  }
*/
int json_condition_immut_alias_deserialize(cJSON *unlock_cond_obj, unlock_cond_list_t **cond_list) {
  if (unlock_cond_obj == NULL || cond_list == NULL) {
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
  unlock_cond_t *unlock_blk = condition_immut_alias_new(&address);
  if (condition_list_add(cond_list, unlock_blk) != 0) {
    printf("[%s:%d] can not add new unlock condition into a list\n", __func__, __LINE__);
    condition_free(unlock_blk);
    return -1;
  }
  condition_free(unlock_blk);

  return 0;
}

static cJSON *json_cond_immut_alias_serialize(unlock_cond_t *cond) {
  if (!cond || cond->type != UNLOCK_COND_IMMUT_ALIAS) {
    printf("[%s:%d] invalid condition\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *addr_obj = cJSON_CreateObject();
  if (addr_obj) {
    // add type to sender
    if (!cJSON_AddNumberToObject(addr_obj, JSON_KEY_TYPE, UNLOCK_COND_IMMUT_ALIAS)) {
      printf("[%s:%d] add type into condition error\n", __func__, __LINE__);
      goto err;
    }

    // add address to sender
    cJSON *addr = json_parser_common_address_serialize((address_t *)cond->obj);
    if (addr) {
      if (!cJSON_AddItemToObject(addr_obj, JSON_KEY_ADDR, addr)) {
        printf("[%s:%d] add address into condition error\n", __func__, __LINE__);
        cJSON_Delete(addr);
        goto err;
      }
    } else {
      cJSON_Delete(addr_obj);
      return NULL;
    }
  }
  return addr_obj;

err:
  cJSON_Delete(addr_obj);
  return NULL;
}

/*
  "unlockConditions": [],
*/
int json_condition_list_deserialize(cJSON *output_obj, unlock_cond_list_t **cond_list) {
  if (output_obj == NULL || cond_list == NULL) {
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

    // unlock condition
    switch (unlock_cond_type) {
      case UNLOCK_COND_ADDRESS:
        if (json_condition_addr_deserialize(elm, cond_list) != 0) {
          printf("[%s:%d] parsing address unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_STORAGE:
        if (json_condition_storage_deserialize(elm, cond_list) != 0) {
          printf("[%s:%d] parsing storage deposit return unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_TIMELOCK:
        if (json_condition_timelock_deserialize(elm, cond_list) != 0) {
          printf("[%s:%d] parsing timelock unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_EXPIRATION:
        if (json_condition_expir_deserialize(elm, cond_list) != 0) {
          printf("[%s:%d] parsing expiration unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_STATE:
        if (json_condition_state_deserialize(elm, cond_list) != 0) {
          printf("[%s:%d] parsing state controller address unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_GOVERNOR:
        if (json_condition_governor_deserialize(elm, cond_list) != 0) {
          printf("[%s:%d] parsing governor address unlock condition failed\n", __func__, __LINE__);
          return -1;
        }
        break;
      case UNLOCK_COND_IMMUT_ALIAS:
        if (json_condition_immut_alias_deserialize(elm, cond_list) != 0) {
          printf("[%s:%d] parsing immutable alias address unlock condition failed\n", __func__, __LINE__);
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

cJSON *json_condition_list_serialize(unlock_cond_list_t *cond_list) {
  cJSON *unlock_arr = cJSON_CreateArray();
  if (unlock_arr) {
    // empty list
    if (!cond_list) {
      return unlock_arr;
    }

    // add items to array
    cJSON *item = NULL;
    unlock_cond_list_t *elm;
    LL_FOREACH(cond_list, elm) {
      switch (elm->current->type) {
        case UNLOCK_COND_ADDRESS:
          item = json_condition_addr_serialize(elm->current);
          break;
        case UNLOCK_COND_STORAGE:
          item = json_condition_storage_serialize((unlock_cond_storage_t *)elm->current);
          break;
        case UNLOCK_COND_TIMELOCK:
          item = json_condition_timelock_serialize((unlock_cond_timelock_t *)elm->current);
          break;
        case UNLOCK_COND_EXPIRATION:
          item = json_condition_expir_serialize((unlock_cond_expir_t *)elm->current);
          break;
        case UNLOCK_COND_STATE:
          item = json_condition_state_serialize(elm->current);
          break;
        case UNLOCK_COND_GOVERNOR:
          item = json_condition_governor_serialize(elm->current);
          break;
        case UNLOCK_COND_IMMUT_ALIAS:
          item = json_cond_immut_alias_serialize(elm->current);
          break;
        default:
          printf("[%s:%d] unsupported unlock condition\n", __func__, __LINE__);
          break;
      }

      if (item) {
        // add item to array
        if (!cJSON_AddItemToArray(unlock_arr, item)) {
          printf("[%s:%d] add condition to array error\n", __func__, __LINE__);
          cJSON_Delete(item);
          cJSON_Delete(unlock_arr);
          return NULL;
        }
      } else {
        printf("[%s:%d] serialize unlock conditions error\n", __func__, __LINE__);
        cJSON_Delete(unlock_arr);
        return NULL;
      }
    }
  }
  return unlock_arr;
}
