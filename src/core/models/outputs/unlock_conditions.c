// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/outputs/unlock_conditions.h"
#include "utlist.h"

static unlock_cond_dust_t* cond_dust_new(address_t const* const addr, uint64_t amount) {
  if (!addr || amount == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_dust_t* dust = malloc(sizeof(unlock_cond_dust_t));
  if (dust) {
    dust->addr = address_clone(addr);
    if (!dust->addr) {
      free(dust);
      return NULL;
    }
    dust->amount = amount;
    return dust;
  }
  return dust;
}

static size_t cond_dust_serialize_len(unlock_cond_dust_t* dust) {
  // return address + return amount
  return address_serialized_len(dust->addr) + sizeof(dust->amount);
}

static size_t cond_dust_serialize(unlock_cond_dust_t* dust, byte_t buf[], size_t buf_len) {
  // serialize address and amount
  size_t offset = address_serialize(dust->addr, buf, buf_len);
  if (offset) {
    memcpy(buf + offset, &dust->amount, sizeof(dust->amount));
    offset += sizeof(dust->amount);
  } else {
    printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
  }
  return offset;
}

static void cond_dust_free(unlock_cond_dust_t* dust) {
  if (dust) {
    if (dust->addr) {
      free_address(dust->addr);
    }
    free(dust);
  }
}

static unlock_cond_dust_t* cond_dust_deserialize(byte_t buf[], size_t buf_len) {
  unlock_cond_dust_t* d = malloc(sizeof(unlock_cond_dust_t));
  if (d) {
    // address
    d->addr = address_deserialize(buf, buf_len);
    if (d->addr) {
      size_t offset = address_serialized_len(d->addr);
      if (buf_len < (offset + sizeof(d->amount))) {
        printf("[%s:%d] insufficient buffer size\n", __func__, __LINE__);
        cond_dust_free(d);
        return NULL;
      }
      // amount
      memcpy(&d->amount, buf + address_serialized_len(d->addr), sizeof(d->amount));
    } else {
      printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
      cond_dust_free(d);
      return NULL;
    }
  }
  return d;
}

static unlock_cond_timelock_t* cond_timelock_new(uint32_t milestone, uint32_t time) {
  if (milestone == 0 && time == 0) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_timelock_t* timelock = malloc(sizeof(unlock_cond_timelock_t));
  if (timelock) {
    timelock->milestone = milestone;
    timelock->time = time;
    return timelock;
  }
  return timelock;
}

static size_t cond_timelock_serialize_len(unlock_cond_timelock_t* t) {
  // milestone index + unix time
  return sizeof(t->milestone) + sizeof(t->time);
}

static size_t cond_timelock_serialize(unlock_cond_timelock_t* t, byte_t buf[], size_t buf_len) {
  // serialize milestone and time
  memcpy(buf, &t->milestone, sizeof(t->milestone));
  size_t offset = sizeof(t->milestone);
  memcpy(buf + offset, &t->time, sizeof(t->time));
  offset += sizeof(t->time);
  return offset;
}

static unlock_cond_timelock_t* cond_timelock_deserialize(byte_t buf[], size_t buf_len) {
  if (buf_len < sizeof(unlock_cond_timelock_t)) {
    printf("[%s:%d] insufficient buffer size\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_timelock_t* t = malloc(sizeof(unlock_cond_timelock_t));
  if (t) {
    memcpy(&t->milestone, buf, sizeof(t->milestone));
    memcpy(&t->time, buf + sizeof(t->milestone), sizeof(t->time));
  }
  return t;
}

static void cond_timelock_free(unlock_cond_timelock_t* timelock) {
  if (timelock) {
    free(timelock);
  }
}

static unlock_cond_expir_t* cond_expir_new(address_t const* const addr, uint32_t milestone, uint32_t time) {
  if (!addr || (milestone == 0 && time == 0)) {
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
    expir->milestone = milestone;
    expir->time = time;
    return expir;
  }
  return expir;
}

static size_t cond_expir_serialize_len(unlock_cond_expir_t* e) {
  // return address + milestone index + unix time
  return address_serialized_len((address_t*)e->addr) + sizeof(e->milestone) + sizeof(e->time);
}

static size_t cond_expir_serialize(unlock_cond_expir_t* e, byte_t buf[], size_t buf_len) {
  // serialize address
  size_t offset = address_serialize(e->addr, buf, buf_len);
  if (offset == 0) {
    printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
    return offset;
  }

  // serialize milestone and time
  memcpy(buf + offset, &e->milestone, sizeof(e->milestone));
  offset += sizeof(e->milestone);
  memcpy(buf + offset, &e->time, sizeof(e->time));
  offset += sizeof(e->time);
  return offset;
}

static void cond_expir_free(unlock_cond_expir_t* expir) {
  if (expir) {
    if (expir->addr) {
      free_address(expir->addr);
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
      if ((buf_len - offset) < (sizeof(e->milestone) + sizeof(e->time))) {
        printf("[%s:%d] insufficient buffer size\n", __func__, __LINE__);
        cond_expir_free(e);
        return NULL;
      }
      // deserialize milestone and time
      memcpy(&e->milestone, buf + offset, sizeof(e->milestone));
      memcpy(&e->time, buf + offset + sizeof(e->milestone), sizeof(e->time));
    } else {
      cond_expir_free(e);
      return NULL;
    }
  }
  return e;
}

// unlock condition blocks must be sorted in ascending order based on the block type
static int cond_blk_type_sort(cond_blk_list_t* blk1, cond_blk_list_t* blk2) {
  return memcmp(&blk1->blk->type, &blk2->blk->type, sizeof(uint8_t));
}

unlock_cond_blk_t* cond_blk_addr_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_blk_t* blk = malloc(sizeof(unlock_cond_blk_t));
  if (blk) {
    blk->block = address_clone(addr);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_ADDRESS;
    return blk;
  }
  return blk;
}

unlock_cond_blk_t* cond_blk_dust_new(address_t const* const addr, uint64_t amount) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_blk_t* blk = malloc(sizeof(unlock_cond_blk_t));
  if (blk) {
    blk->block = cond_dust_new(addr, amount);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_DUST;
    return blk;
  }
  return blk;
}

unlock_cond_blk_t* cond_blk_timelock_new(uint32_t milestone, uint32_t time) {
  unlock_cond_blk_t* blk = malloc(sizeof(unlock_cond_blk_t));
  if (blk) {
    blk->block = cond_timelock_new(milestone, time);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_TIMELOCK;
    return blk;
  }
  return blk;
}

unlock_cond_blk_t* cond_blk_expir_new(address_t const* const addr, uint32_t milestone, uint32_t time) {
  unlock_cond_blk_t* blk = malloc(sizeof(unlock_cond_blk_t));
  if (blk) {
    blk->block = cond_expir_new(addr, milestone, time);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_EXPIRATION;
    return blk;
  }
  return blk;
}

unlock_cond_blk_t* cond_blk_state_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_blk_t* blk = malloc(sizeof(unlock_cond_blk_t));
  if (blk) {
    blk->block = address_clone(addr);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_STATE;
    return blk;
  }
  return blk;
}

unlock_cond_blk_t* cond_blk_governor_new(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_blk_t* blk = malloc(sizeof(unlock_cond_blk_t));
  if (blk) {
    blk->block = address_clone(addr);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_GOVERNOR;
    return blk;
  }
  return blk;
}

size_t cond_blk_serialize_len(unlock_cond_blk_t const* const blk) {
  if (!blk) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  switch (blk->type) {
    case UNLOCK_COND_ADDRESS:
    case UNLOCK_COND_STATE:
    case UNLOCK_COND_GOVERNOR:
      // block type + address
      return sizeof(uint8_t) + address_serialized_len((address_t*)blk->block);
    case UNLOCK_COND_DUST:
      // block type + dust block
      return sizeof(uint8_t) + cond_dust_serialize_len((unlock_cond_dust_t*)blk->block);
    case UNLOCK_COND_TIMELOCK:
      // block type + timelock block
      return sizeof(uint8_t) + cond_timelock_serialize_len((unlock_cond_timelock_t*)blk->block);
    case UNLOCK_COND_EXPIRATION:
      // block type + expiration block
      return sizeof(uint8_t) + cond_expir_serialize_len((unlock_cond_expir_t*)blk->block);
    default:
      printf("[%s:%d] unknown feature block type\n", __func__, __LINE__);
      break;
  }
  return 0;
}

size_t cond_blk_serialize(unlock_cond_blk_t* blk, byte_t buf[], size_t buf_len) {
  if (!blk || !buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;
  size_t expected_bytes = cond_blk_serialize_len(blk);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  // fillin block type
  memcpy(buf, &blk->type, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  switch (blk->type) {
    case UNLOCK_COND_ADDRESS:
    case UNLOCK_COND_STATE:
    case UNLOCK_COND_GOVERNOR:
      offset += address_serialize((address_t*)blk->block, buf + offset, buf_len - offset);
      break;
    case UNLOCK_COND_DUST:
      offset += cond_dust_serialize((unlock_cond_dust_t*)blk->block, buf + offset, buf_len - offset);
      break;
    case UNLOCK_COND_TIMELOCK:
      offset += cond_timelock_serialize((unlock_cond_timelock_t*)blk->block, buf + offset, buf_len - offset);
      break;
    case UNLOCK_COND_EXPIRATION:
      offset += cond_expir_serialize((unlock_cond_expir_t*)blk->block, buf + offset, buf_len - offset);
      break;
    default:
      printf("[%s:%d] invalid condition block\n", __func__, __LINE__);
      break;
  }
  return offset;
}

unlock_cond_blk_t* cond_blk_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_blk_t* blk = malloc(sizeof(unlock_cond_blk_t));
  if (!blk) {
    printf("[%s:%d] creating condition block failed\n", __func__, __LINE__);
    return NULL;
  }

  // fetch block type
  blk->type = buf[0];
  blk->block = NULL;

  switch (blk->type) {
    case UNLOCK_COND_ADDRESS:
    case UNLOCK_COND_STATE:
    case UNLOCK_COND_GOVERNOR:
      // deserialize address
      blk->block = address_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    case UNLOCK_COND_DUST:
      // deserialize dust block
      blk->block = cond_dust_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    case UNLOCK_COND_TIMELOCK:
      // deserialize timelock block
      blk->block = cond_timelock_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    case UNLOCK_COND_EXPIRATION:
      blk->block = cond_expir_deserialize(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t));
      break;
    default:
      break;
  }

  if (!blk->block) {
    printf("[%s:%d] deserialize block failed\n", __func__, __LINE__);
    free(blk);
    return NULL;
  }
  return blk;
}

unlock_cond_blk_t* cond_blk_clone(unlock_cond_blk_t* blk) {
  if (!blk) {
    return NULL;
  }

  switch (blk->type) {
    case UNLOCK_COND_ADDRESS:
      return cond_blk_addr_new((address_t*)blk->block);
    case UNLOCK_COND_DUST: {
      unlock_cond_dust_t* dust = (unlock_cond_dust_t*)blk->block;
      return cond_blk_dust_new(dust->addr, dust->amount);
    }
    case UNLOCK_COND_TIMELOCK: {
      unlock_cond_timelock_t* t = (unlock_cond_timelock_t*)blk->block;
      return cond_blk_timelock_new(t->milestone, t->time);
    }
    case UNLOCK_COND_EXPIRATION: {
      unlock_cond_expir_t* e = (unlock_cond_expir_t*)blk->block;
      return cond_blk_expir_new(e->addr, e->milestone, e->time);
    }
    case UNLOCK_COND_STATE:
      return cond_blk_state_new((address_t*)blk->block);
    case UNLOCK_COND_GOVERNOR:
      return cond_blk_governor_new((address_t*)blk->block);
    default:
      break;
  }
  return NULL;
}

void cond_blk_free(unlock_cond_blk_t* blk) {
  if (blk) {
    switch (blk->type) {
      case UNLOCK_COND_ADDRESS:
      case UNLOCK_COND_STATE:
      case UNLOCK_COND_GOVERNOR:
        free_address((address_t*)blk->block);
        break;
      case UNLOCK_COND_DUST:
        cond_dust_free((unlock_cond_dust_t*)blk->block);
        break;
      case UNLOCK_COND_TIMELOCK:
        cond_timelock_free((unlock_cond_timelock_t*)blk->block);
        break;
      case UNLOCK_COND_EXPIRATION:
        cond_expir_free((unlock_cond_expir_t*)blk->block);
        break;
    }
    free(blk);
  }
}

void cond_blk_print(unlock_cond_blk_t* blk) {
  if (!blk) {
    return;
  }

  switch (blk->type) {
    case UNLOCK_COND_ADDRESS:
      printf("Address:");
      address_print((address_t*)blk->block);
      break;
    case UNLOCK_COND_DUST:
      printf("Dust Return Amount: %" PRIu64 ", Return Address: ", ((unlock_cond_dust_t*)blk->block)->amount);
      address_print(((unlock_cond_dust_t*)blk->block)->addr);
      break;
    case UNLOCK_COND_TIMELOCK:
      printf("Timelock: Milestone %" PRIu32 ", Unix %" PRIu32 "\n", ((unlock_cond_timelock_t*)blk->block)->milestone,
             ((unlock_cond_timelock_t*)blk->block)->time);
      break;
    case UNLOCK_COND_EXPIRATION:
      printf("Expiration: Milestone %" PRIu32 ", Unix %" PRIu32 ", Address ",
             ((unlock_cond_expir_t*)blk->block)->milestone, ((unlock_cond_expir_t*)blk->block)->time);
      address_print(((unlock_cond_expir_t*)blk->block)->addr);
      break;
    case UNLOCK_COND_STATE:
      printf("State Controller Address:");
      address_print((address_t*)blk->block);
      break;
    case UNLOCK_COND_GOVERNOR:
      printf("Governor Address:");
      address_print((address_t*)blk->block);
      break;
    default:
      break;
  }
}

cond_blk_list_t* cond_blk_list_new() { return NULL; }

int cond_blk_list_add(cond_blk_list_t** list, unlock_cond_blk_t* blk) {
  // at most one of each block
  if (cond_blk_list_get_type(*list, blk->type)) {
    printf("[%s:%d] block type %d exists in the list\n", __func__, __LINE__, blk->type);
    return -1;
  }

  cond_blk_list_t* next = malloc(sizeof(cond_blk_list_t));
  if (next) {
    next->blk = cond_blk_clone(blk);
    if (next->blk) {
      LL_APPEND(*list, next);
      return 0;
    } else {
      free(next);
    }
  }
  return -1;
}

uint8_t cond_blk_list_len(cond_blk_list_t* list) {
  cond_blk_list_t* elm = NULL;
  uint8_t len = 0;

  if (list) {
    LL_COUNT(list, elm, len);
    return len;
  }
  return len;
}

unlock_cond_blk_t* cond_blk_list_get(cond_blk_list_t* list, uint8_t index) {
  uint8_t count = 0;
  cond_blk_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (count == index) {
        return elm->blk;
      }
      count++;
    }
  }
  return NULL;
}

unlock_cond_blk_t* cond_blk_list_get_type(cond_blk_list_t* list, unlock_cond_e type) {
  cond_blk_list_t* elm;
  if (list) {
    LL_FOREACH(list, elm) {
      if (elm->blk->type == type) {
        return elm->blk;
      }
    }
  }
  return NULL;
}

void cond_blk_list_sort(cond_blk_list_t** list) {
  // sort unlock condition blocks in ascending order based on the block type
  LL_SORT(*list, cond_blk_type_sort);
}

int cond_blk_list_syntactic(cond_blk_list_t** list) {
  // 1 ≤ Unlock Conditions Count ≤ 4
  if (!list || !*list) {
    printf("[%s:%d] empty list\n", __func__, __LINE__);
    return -1;
  }

  if (cond_blk_list_len(*list) > MAX_UNLOCK_CONDITION_BLOCK_COUNT) {
    printf("[%s:%d] Unlock condition count must less than %d\n", __func__, __LINE__, MAX_UNLOCK_CONDITION_BLOCK_COUNT);
    return -1;
  }

  // sort block types
  cond_blk_list_sort(list);

  // // Address Unlock Condition must be present
  // if (cond_blk_list_get(*list, 0)->type != UNLOCK_COND_ADDRESS) {
  //   printf("[%s:%d] Address Unlock Condition must be present\n", __func__, __LINE__);
  //   return -1;
  // }

  return 0;
}

size_t cond_blk_list_serialize_len(cond_blk_list_t* list) {
  cond_blk_list_t* elm;
  // block count
  size_t len = sizeof(uint8_t);
  // blocks
  if (list) {
    LL_FOREACH(list, elm) { len += cond_blk_serialize_len(elm->blk); }
  }
  return len;
}

size_t cond_blk_list_serialize(cond_blk_list_t** list, byte_t buf[], size_t buf_len) {
  if (cond_blk_list_syntactic(list) == 0) {
    // serialized len = block count + blocks
    size_t expected_bytes = cond_blk_list_serialize_len(*list);
    if (buf_len < expected_bytes) {
      printf("[%s:%d] insufficent buffer size\n", __func__, __LINE__);
      return 0;
    }

    cond_blk_list_t* elm;
    size_t offset = sizeof(uint8_t);
    // block count
    buf[0] = cond_blk_list_len(*list);
    // serialized blocks
    LL_FOREACH(*list, elm) { offset += cond_blk_serialize(elm->blk, buf + offset, buf_len - offset); }
    // check the length of the serialized data
    if (offset != expected_bytes) {
      printf("[%s:%d] offset is not matched with expectation\n", __func__, __LINE__);
      return 0;
    }
    return offset;
  }
  return 0;
}

cond_blk_list_t* cond_blk_list_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len <= 1) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  cond_blk_list_t* list = cond_blk_list_new();
  size_t offset = sizeof(uint8_t);
  uint8_t blk_cnt = buf[0];
  for (uint8_t i = 0; i < blk_cnt; i++) {
    cond_blk_list_t* new_cond = malloc(sizeof(cond_blk_list_t));
    if (new_cond) {
      new_cond->blk = cond_blk_deserialize(buf + offset, buf_len - offset);
      if (new_cond->blk) {
        // offset of the next block
        offset += cond_blk_serialize_len(new_cond->blk);
        LL_APPEND(list, new_cond);
      } else {
        free(new_cond);
        cond_blk_list_free(list);
        return NULL;
      }
    } else {
      // error on new condition block list
      cond_blk_list_free(list);
      return NULL;
    }
  }
  return list;
}

void cond_blk_list_free(cond_blk_list_t* list) {
  cond_blk_list_t *elm, *tmp;
  if (list) {
    LL_FOREACH_SAFE(list, elm, tmp) {
      cond_blk_free(elm->blk);
      LL_DELETE(list, elm);
      free(elm);
    }
  }
}

cond_blk_list_t* cond_blk_list_clone(cond_blk_list_t const* const list) {
  if (!list) {
    return NULL;
  }

  cond_blk_list_t* new_list = cond_blk_list_new();
  cond_blk_list_t* elm;
  LL_FOREACH((cond_blk_list_t*)list, elm) {
    if (cond_blk_list_add(&new_list, elm->blk) != 0) {
      printf("[%s:%d] add condition block to list failed\n", __func__, __LINE__);
      cond_blk_list_free(new_list);
      return NULL;
    }
  }
  return new_list;
}

void cond_blk_list_print(cond_blk_list_t* list, uint8_t indent) {
  cond_blk_list_t* elm;
  uint8_t index = 0;
  printf("%sUnlock Conditions: [\n", PRINT_INDENTATION(indent));
  printf("%s\tBlock Count: %d\n", PRINT_INDENTATION(indent), cond_blk_list_len(list));
  if (list) {
    LL_FOREACH(list, elm) {
      printf("%s\t#%d ", PRINT_INDENTATION(indent), index);
      cond_blk_print(elm->blk);
      index++;
    }
  }
  printf("%s]\n", PRINT_INDENTATION(indent));
}
