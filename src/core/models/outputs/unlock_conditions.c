// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/outputs/unlock_conditions.h"
#include "core/utils/macros.h"
#include "utlist.h"

static unlock_cond_storage_t* cond_storage_new(address_t const* const addr, uint64_t amount) {
  if (!addr || amount == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_storage_t* storage = malloc(sizeof(unlock_cond_storage_t));
  if (storage) {
    storage->addr = address_clone(addr);
    if (!storage->addr) {
      free(storage);
      return NULL;
    }
    storage->amount = amount;
    return storage;
  }
  return storage;
}

static size_t cond_storage_serialize_len(unlock_cond_storage_t* storage) {
  // return address + return amount
  return address_serialized_len(storage->addr) + sizeof(storage->amount);
}

static size_t cond_storage_serialize(unlock_cond_storage_t* storage, byte_t buf[], size_t buf_len) {
  // serialize address and amount
  size_t offset = address_serialize(storage->addr, buf, buf_len);
  if (offset) {
    memcpy(buf + offset, &storage->amount, sizeof(storage->amount));
    offset += sizeof(storage->amount);
  } else {
    printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
  }
  return offset;
}

static void cond_storage_free(unlock_cond_storage_t* storage) {
  if (storage) {
    if (storage->addr) {
      address_free(storage->addr);
    }
    free(storage);
  }
}

static unlock_cond_storage_t* cond_storage_deserialize(byte_t buf[], size_t buf_len) {
  unlock_cond_storage_t* d = malloc(sizeof(unlock_cond_storage_t));
  if (d) {
    // address
    d->addr = address_deserialize(buf, buf_len);
    if (d->addr) {
      size_t offset = address_serialized_len(d->addr);
      if (buf_len < (offset + sizeof(d->amount))) {
        printf("[%s:%d] insufficient buffer size\n", __func__, __LINE__);
        cond_storage_free(d);
        return NULL;
      }
      // amount
      memcpy(&d->amount, buf + address_serialized_len(d->addr), sizeof(d->amount));
    } else {
      printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
      cond_storage_free(d);
      return NULL;
    }
  }
  return d;
}

static unlock_cond_timelock_t* cond_timelock_new(uint32_t time) {
  if (time == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_timelock_t* timelock = malloc(sizeof(unlock_cond_timelock_t));
  if (timelock) {
    timelock->time = time;
    return timelock;
  }
  return timelock;
}

static size_t cond_timelock_serialize_len(unlock_cond_timelock_t* t) {
  // Unix time
  return sizeof(t->time);
}

static size_t cond_timelock_serialize(unlock_cond_timelock_t* t, byte_t buf[], size_t buf_len) {
  if (buf_len >= sizeof(t->time)) {
    // serialize time
    memcpy(buf, &t->time, sizeof(t->time));
    return sizeof(t->time);
  }

  printf("[%s:%d] timelock serialization failed\n", __func__, __LINE__);
  return 0;
}

static unlock_cond_timelock_t* cond_timelock_deserialize(byte_t buf[], size_t buf_len) {
  if (buf_len < sizeof(unlock_cond_timelock_t)) {
    printf("[%s:%d] insufficient buffer size\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_timelock_t* t = malloc(sizeof(unlock_cond_timelock_t));
  if (t) {
    memcpy(&t->time, buf, sizeof(t->time));
  }
  return t;
}

static void cond_timelock_free(unlock_cond_timelock_t* timelock) {
  if (timelock) {
    free(timelock);
  }
}

static unlock_cond_expir_t* cond_expir_new(address_t const* const addr, uint32_t time) {
  if (!addr || time == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_expir_t* expir = malloc(sizeof(unlock_cond_expir_t));
  if (expir) {
    expir->addr = address_clone(addr);
    if (!expir->addr) {
      free(expir);
      return NULL;
    }
    expir->time = time;
    return expir;
  }
  return expir;
}

static size_t cond_expir_serialize_len(unlock_cond_expir_t* e) {
  // return address + milestone index + unix time
  return address_serialized_len((address_t*)e->addr) + sizeof(e->time);
}

static size_t cond_expir_serialize(unlock_cond_expir_t* e, byte_t buf[], size_t buf_len) {
  // serialize address
  size_t offset = address_serialize(e->addr, buf, buf_len);
  if (offset == 0) {
    printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
    return offset;
  }

  // serialize time
  memcpy(buf + offset, &e->time, sizeof(e->time));
  offset += sizeof(e->time);
  return offset;
}

static void cond_expir_free(unlock_cond_expir_t* expir) {
  if (expir) {
    if (expir->addr) {
      address_free(expir->addr);
    }
    free(expir);
  }
}

static unlock_cond_expir_t* cond_expir_deserialize(byte_t buf[], size_t buf_len) {
  unlock_cond_expir_t* e = malloc(sizeof(unlock_cond_expir_t));
  if (e) {
    e->addr = address_deserialize(buf, buf_len);
    if (e->addr) {
      size_t offset = address_serialized_len(e->addr);
      if ((buf_len - offset) < sizeof(e->time)) {
        printf("[%s:%d] insufficient buffer size\n", __func__, __LINE__);
        cond_expir_free(e);
        return NULL;
      }
      // deserialize time
      memcpy(&e->time, buf + offset, sizeof(e->time));
    } else {
      cond_expir_free(e);
      return NULL;
    }
  }
  return e;
}

// unlock conditions must be sorted in ascending order based on the unlock condition type
static int condition_type_sort(unlock_cond_list_t* list1, unlock_cond_list_t* list2) {
  return memcmp(&list1->current->type, &list2->current->type, sizeof(uint8_t));
}

unlock_cond_t* condition_addr_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (cond) {
    cond->obj = address_clone(addr);
    if (!cond->obj) {
      free(cond);
      return NULL;
    }
    cond->type = UNLOCK_COND_ADDRESS;
    return cond;
  }
  return cond;
}

unlock_cond_t* condition_storage_new(address_t const* const addr, uint64_t amount) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (cond) {
    cond->obj = cond_storage_new(addr, amount);
    if (!cond->obj) {
      free(cond);
      return NULL;
    }
    cond->type = UNLOCK_COND_STORAGE;
    return cond;
  }
  return cond;
}

unlock_cond_t* condition_timelock_new(uint32_t time) {
  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (cond) {
    cond->obj = cond_timelock_new(time);
    if (!cond->obj) {
      free(cond);
      return NULL;
    }
    cond->type = UNLOCK_COND_TIMELOCK;
    return cond;
  }
  return cond;
}

unlock_cond_t* condition_expir_new(address_t const* const addr, uint32_t time) {
  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (cond) {
    cond->obj = cond_expir_new(addr, time);
    if (!cond->obj) {
      free(cond);
      return NULL;
    }
    cond->type = UNLOCK_COND_EXPIRATION;
    return cond;
  }
  return cond;
}

unlock_cond_t* condition_state_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (cond) {
    cond->obj = address_clone(addr);
    if (!cond->obj) {
      free(cond);
      return NULL;
    }
    cond->type = UNLOCK_COND_STATE;
    return cond;
  }
  return cond;
}

unlock_cond_t* condition_governor_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (cond) {
    cond->obj = address_clone(addr);
    if (!cond->obj) {
      free(cond);
      return NULL;
    }
    cond->type = UNLOCK_COND_GOVERNOR;
    return cond;
  }
  return cond;
}

unlock_cond_t* condition_immut_alias_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  if (addr->type != ADDRESS_TYPE_ALIAS) {
    printf("[%s:%d] must be Alias address\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (cond) {
    cond->obj = address_clone(addr);
    if (!cond->obj) {
      free(cond);
      return NULL;
    }
    cond->type = UNLOCK_COND_IMMUT_ALIAS;
    return cond;
  }
  return cond;
}

size_t condition_serialize_len(unlock_cond_t const* const cond) {
  if (!cond) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  switch (cond->type) {
    case UNLOCK_COND_ADDRESS:
    case UNLOCK_COND_STATE:
    case UNLOCK_COND_GOVERNOR:
    case UNLOCK_COND_IMMUT_ALIAS:
      // condition type + address
      return sizeof(uint8_t) + address_serialized_len((address_t*)cond->obj);
    case UNLOCK_COND_STORAGE:
      // confition type + storage unlock condition
      return sizeof(uint8_t) + cond_storage_serialize_len((unlock_cond_storage_t*)cond->obj);
    case UNLOCK_COND_TIMELOCK:
      // condition type + timelock unlock condition
      return sizeof(uint8_t) + cond_timelock_serialize_len((unlock_cond_timelock_t*)cond->obj);
    case UNLOCK_COND_EXPIRATION:
      // condition type + expiration unlock condtion
      return sizeof(uint8_t) + cond_expir_serialize_len((unlock_cond_expir_t*)cond->obj);
    default:
      printf("[%s:%d] unknown unlock condition type\n", __func__, __LINE__);
      break;
  }
  return 0;
}

size_t condition_serialize(unlock_cond_t* cond, byte_t buf[], size_t buf_len) {
  if (!cond || !buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;
  size_t expected_bytes = condition_serialize_len(cond);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  // fillin unlock condition type
  memcpy(buf, &cond->type, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  switch (cond->type) {
    case UNLOCK_COND_ADDRESS:
    case UNLOCK_COND_STATE:
    case UNLOCK_COND_GOVERNOR:
    case UNLOCK_COND_IMMUT_ALIAS:
      offset += address_serialize((address_t*)cond->obj, buf + offset, buf_len - offset);
      break;
    case UNLOCK_COND_STORAGE:
      offset += cond_storage_serialize((unlock_cond_storage_t*)cond->obj, buf + offset, buf_len - offset);
      break;
    case UNLOCK_COND_TIMELOCK:
      offset += cond_timelock_serialize((unlock_cond_timelock_t*)cond->obj, buf + offset, buf_len - offset);
      break;
    case UNLOCK_COND_EXPIRATION:
      offset += cond_expir_serialize((unlock_cond_expir_t*)cond->obj, buf + offset, buf_len - offset);
      break;
    default:
      printf("[%s:%d] invalid unlock condition\n", __func__, __LINE__);
      break;
  }
  return offset;
}

unlock_cond_t* condition_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_t* cond = malloc(sizeof(unlock_cond_t));
  if (!cond) {
    printf("[%s:%d] creating unlock condition failed\n", __func__, __LINE__);
    return NULL;
  }

  // fetch unlock condition type
  cond->type = buf[0];
  cond->obj = NULL;

  switch (cond->type) {
    case UNLOCK_COND_ADDRESS:
    case UNLOCK_COND_STATE:
    case UNLOCK_COND_GOVERNOR:
    case UNLOCK_COND_IMMUT_ALIAS:
      // deserialize address
      cond->obj = address_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    case UNLOCK_COND_STORAGE:
      // deserialize storage unlock condition
      cond->obj = cond_storage_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    case UNLOCK_COND_TIMELOCK:
      // deserialize timelock unlock condtion
      cond->obj = cond_timelock_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    case UNLOCK_COND_EXPIRATION:
      cond->obj = cond_expir_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    default:
      break;
  }

  if (!cond->obj) {
    printf("[%s:%d] deserialize unlock condition failed\n", __func__, __LINE__);
    free(cond);
    return NULL;
  }
  return cond;
}

unlock_cond_t* condition_clone(unlock_cond_t* cond) {
  if (!cond) {
    return NULL;
  }

  switch (cond->type) {
    case UNLOCK_COND_ADDRESS:
      return condition_addr_new((address_t*)cond->obj);
    case UNLOCK_COND_STORAGE: {
      unlock_cond_storage_t* storage = (unlock_cond_storage_t*)cond->obj;
      return condition_storage_new(storage->addr, storage->amount);
    }
    case UNLOCK_COND_TIMELOCK: {
      unlock_cond_timelock_t* t = (unlock_cond_timelock_t*)cond->obj;
      return condition_timelock_new(t->time);
    }
    case UNLOCK_COND_EXPIRATION: {
      unlock_cond_expir_t* e = (unlock_cond_expir_t*)cond->obj;
      return condition_expir_new(e->addr, e->time);
    }
    case UNLOCK_COND_STATE:
      return condition_state_new((address_t*)cond->obj);
    case UNLOCK_COND_GOVERNOR:
      return condition_governor_new((address_t*)cond->obj);
    case UNLOCK_COND_IMMUT_ALIAS:
      return condition_immut_alias_new((address_t*)cond->obj);
    default:
      break;
  }
  return NULL;
}

void condition_free(unlock_cond_t* cond) {
  if (cond) {
    switch (cond->type) {
      case UNLOCK_COND_ADDRESS:
      case UNLOCK_COND_STATE:
      case UNLOCK_COND_GOVERNOR:
      case UNLOCK_COND_IMMUT_ALIAS:
        address_free((address_t*)cond->obj);
        break;
      case UNLOCK_COND_STORAGE:
        cond_storage_free((unlock_cond_storage_t*)cond->obj);
        break;
      case UNLOCK_COND_TIMELOCK:
        cond_timelock_free((unlock_cond_timelock_t*)cond->obj);
        break;
      case UNLOCK_COND_EXPIRATION:
        cond_expir_free((unlock_cond_expir_t*)cond->obj);
        break;
    }
    free(cond);
  }
}

void condition_print(unlock_cond_t* cond) {
  if (!cond) {
    return;
  }

  switch (cond->type) {
    case UNLOCK_COND_ADDRESS:
      printf("Address:");
      address_print((address_t*)cond->obj);
      break;
    case UNLOCK_COND_STORAGE:
      printf("Storage Return Amount: %" PRIu64 ", Return Address: ", ((unlock_cond_storage_t*)cond->obj)->amount);
      address_print(((unlock_cond_storage_t*)cond->obj)->addr);
      break;
    case UNLOCK_COND_TIMELOCK:
      printf("Timelock: Unix %" PRIu32 "\n", ((unlock_cond_timelock_t*)cond->obj)->time);
      break;
    case UNLOCK_COND_EXPIRATION:
      printf("Expiration: Unix %" PRIu32 ", Address ", ((unlock_cond_expir_t*)cond->obj)->time);
      address_print(((unlock_cond_expir_t*)cond->obj)->addr);
      break;
    case UNLOCK_COND_STATE:
      printf("State Controller Address:");
      address_print((address_t*)cond->obj);
      break;
    case UNLOCK_COND_GOVERNOR:
      printf("Governor Address:");
      address_print((address_t*)cond->obj);
      break;
    case UNLOCK_COND_IMMUT_ALIAS:
      printf("Immutable Alias Address:");
      address_print((address_t*)cond->obj);
      break;
    default:
      break;
  }
}

unlock_cond_list_t* condition_list_new() { return NULL; }

int condition_list_add(unlock_cond_list_t** list, unlock_cond_t* cond) {
  // at most one of each unlock condition
  if (condition_list_get_type(*list, cond->type)) {
    printf("[%s:%d] unlock condition type %d exists in the list\n", __func__, __LINE__, cond->type);
    return -1;
  }

  unlock_cond_list_t* next = malloc(sizeof(unlock_cond_list_t));
  if (next) {
    next->current = condition_clone(cond);
    if (next->current) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }
  return -1;
}

uint8_t condition_list_len(unlock_cond_list_t* list) {
  unlock_cond_list_t* elm = NULL;
  uint8_t len = 0;

  if (list) {
    LL_COUNT(list, elm, len);
    return len;
  }
  return len;
}

unlock_cond_t* condition_list_get(unlock_cond_list_t* list, uint8_t index) {
  uint8_t count = 0;
  unlock_cond_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (count == index) {
        return elm->current;
      }
      count++;
    }
  }
  return NULL;
}

unlock_cond_t* condition_list_get_type(unlock_cond_list_t* list, unlock_cond_type_e type) {
  unlock_cond_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (elm->current->type == type) {
        return elm->current;
      }
    }
  }
  return NULL;
}

void condition_list_sort(unlock_cond_list_t** list) {
  // sort unlock conditions in ascending order based on the condition type
  LL_SORT(*list, condition_type_sort);
}

int condition_list_syntactic(unlock_cond_list_t** list) {
  // 1 ≤ Unlock Conditions Count ≤ 4
  if (!list || !*list) {
    printf("[%s:%d] empty list\n", __func__, __LINE__);
    return -1;
  }

  if (condition_list_len(*list) > MAX_UNLOCK_CONDITION_BLOCK_COUNT) {
    printf("[%s:%d] Unlock condition count must less than %d\n", __func__, __LINE__, MAX_UNLOCK_CONDITION_BLOCK_COUNT);
    return -1;
  }

  // sort unlock condition types
  condition_list_sort(list);

  return 0;
}

size_t condition_list_serialize_len(unlock_cond_list_t* list) {
  unlock_cond_list_t* elm;
  // unlock condition count
  size_t len = sizeof(uint8_t);
  // unlock conditions
  if (list) {
    LL_FOREACH(list, elm) { len += condition_serialize_len(elm->current); }
  }
  return len;
}

size_t condition_list_serialize(unlock_cond_list_t** list, byte_t buf[], size_t buf_len) {
  if (condition_list_syntactic(list) == 0) {
    // serialized len = condition count + unlock conditions
    size_t expected_bytes = condition_list_serialize_len(*list);
    if (buf_len < expected_bytes) {
      printf("[%s:%d] insufficent buffer size\n", __func__, __LINE__);
      return 0;
    }

    unlock_cond_list_t* elm;
    size_t offset = sizeof(uint8_t);
    // condition count
    buf[0] = condition_list_len(*list);
    // serialized unlock conditions
    LL_FOREACH(*list, elm) { offset += condition_serialize(elm->current, buf + offset, buf_len - offset); }
    // check the length of the serialized data
    if (offset != expected_bytes) {
      printf("[%s:%d] offset is not matched with expectation\n", __func__, __LINE__);
      return 0;
    }
    return offset;
  }
  return 0;
}

unlock_cond_list_t* condition_list_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len <= 1) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_list_t* list = condition_list_new();
  size_t offset = sizeof(uint8_t);
  uint8_t cond_cnt = buf[0];
  for (uint8_t i = 0; i < cond_cnt; i++) {
    unlock_cond_list_t* new_cond = malloc(sizeof(unlock_cond_list_t));
    if (new_cond) {
      new_cond->current = condition_deserialize(buf + offset, buf_len - offset);
      if (new_cond->current) {
        // offset of the next unlock condition
        offset += condition_serialize_len(new_cond->current);
        LL_APPEND(list, new_cond);
      } else {
        free(new_cond);
        condition_list_free(list);
        return NULL;
      }
    } else {
      // error on new unlock condition list
      condition_list_free(list);
      return NULL;
    }
  }
  return list;
}

void condition_list_free(unlock_cond_list_t* list) {
  unlock_cond_list_t *elm, *tmp;
  if (list) {
    LL_FOREACH_SAFE(list, elm, tmp) {
      condition_free(elm->current);
      LL_DELETE(list, elm);
      free(elm);
    }
  }
}

unlock_cond_list_t* condition_list_clone(unlock_cond_list_t const* const list) {
  if (!list) {
    return NULL;
  }

  unlock_cond_list_t* new_list = condition_list_new();
  unlock_cond_list_t* elm;
  LL_FOREACH((unlock_cond_list_t*)list, elm) {
    if (condition_list_add(&new_list, elm->current) != 0) {
      printf("[%s:%d] add unlock condition to list failed\n", __func__, __LINE__);
      condition_list_free(new_list);
      return NULL;
    }
  }
  return new_list;
}

void condition_list_print(unlock_cond_list_t* list, uint8_t indent) {
  unlock_cond_list_t* elm;
  uint8_t index = 0;
  printf("%sUnlock Conditions: [\n", PRINT_INDENTATION(indent));
  printf("%s\tBlock Count: %d\n", PRINT_INDENTATION(indent), condition_list_len(list));
  if (list) {
    LL_FOREACH(list, elm) {
      printf("%s\t#%d ", PRINT_INDENTATION(indent), index);
      condition_print(elm->current);
      index++;
    }
  }
  printf("%s]\n", PRINT_INDENTATION(indent));
}
