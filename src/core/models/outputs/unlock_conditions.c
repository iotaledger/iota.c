// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/outputs/unlock_conditions.h"

static unlock_cond_dust_t* new_cond_dust(address_t const* const addr, uint64_t amount) {
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
  return address_serialized_len((address_t*)dust->addr) + sizeof(dust->amount);
}

static size_t cond_dust_serialize(unlock_cond_dust_t* dust, byte_t buf[], size_t buf_len) {
  // serialize address and amount
  size_t offset = address_serialize((address_t*)dust->addr, buf + offset, buf_len - offset);
  if (offset) {
    memcpy(buf + offset, &dust->amount, sizeof(dust->amount));
    offset += sizeof(dust->amount);
  } else {
    printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
  }
  return offset;
}

static void free_cond_dust(unlock_cond_dust_t* dust) {
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
      // amount
      memcpy(&d->amount, buf + address_serialized_len(d->addr), sizeof(d->amount));
    } else {
      printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
      free_cond_dust(d);
      return NULL;
    }
  }
  return d;
}

static unlock_cond_timelock_t* new_cond_timelock(uint32_t milestone, uint32_t time) {
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
  unlock_cond_timelock_t* t = malloc(sizeof(unlock_cond_timelock_t));
  if (t) {
    memcpy(&t->milestone, buf, sizeof(t->milestone));
    memcpy(&t->time, buf + sizeof(t->milestone), sizeof(t->time));
  }
  return t;
}

static void free_cond_timelock(unlock_cond_timelock_t* timelock) {
  if (timelock) {
    free(timelock);
  }
}

static unlock_cond_expir_t* new_cond_expir(address_t const* const addr, uint32_t milestone, uint32_t time) {
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

static void free_cond_expir(unlock_cond_expir_t* expir) {
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
      // deserialize milestone and time
      memcpy(&e->milestone, buf + offset, sizeof(e->milestone));
      memcpy(&e->time, buf + offset + sizeof(e->milestone), sizeof(e->time));
    } else {
      free_cond_expir(e);
      return NULL;
    }
  }
  return e;
}

unlock_cond_block_t* new_cond_blk_addr(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_block_t* blk = malloc(sizeof(unlock_cond_block_t));
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

unlock_cond_block_t* new_cond_blk_dust(address_t const* const addr, uint64_t amount) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_block_t* blk = malloc(sizeof(unlock_cond_block_t));
  if (blk) {
    blk->block = new_cond_dust(addr, amount);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_DUST;
    return blk;
  }
  return blk;
}

unlock_cond_block_t* new_cond_blk_timelock(uint32_t milestone, uint32_t time) {
  unlock_cond_block_t* blk = malloc(sizeof(unlock_cond_block_t));
  if (blk) {
    blk->block = new_cond_timelock(milestone, time);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_TIMELOCK;
    return blk;
  }
  return blk;
}

unlock_cond_block_t* new_cond_blk_expir(address_t const* const addr, uint32_t milestone, uint32_t time) {
  unlock_cond_block_t* blk = malloc(sizeof(unlock_cond_block_t));
  if (blk) {
    blk->block = new_cond_expir(addr, milestone, time);
    if (!blk->block) {
      free(blk);
      return NULL;
    }
    blk->type = UNLOCK_COND_EXPIRATION;
    return blk;
  }
  return blk;
}

unlock_cond_block_t* new_cond_blk_state(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_block_t* blk = malloc(sizeof(unlock_cond_block_t));
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

unlock_cond_block_t* new_cond_blk_governor(address_t const* const addr) {
  if (!addr) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_block_t* blk = malloc(sizeof(unlock_cond_block_t));
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

size_t cond_blk_serialize_len(unlock_cond_block_t const* const blk) {
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

size_t cond_blk_serialize(unlock_cond_block_t* blk, byte_t buf[], size_t buf_len) {
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
    case UNLOCK_COND_GOVERNOR: {
      // serialize address object
      size_t add_len = address_serialize((address_t*)blk->block, buf + offset, buf_len - offset);
      if (add_len == 0) {
        printf("[%s:%d] address serialization failed\n", __func__, __LINE__);
      } else {
        offset += add_len;
      }
    }
      return offset;
    case UNLOCK_COND_DUST:
      return cond_dust_serialize((unlock_cond_dust_t*)blk->block, buf + offset, buf_len - offset);
    case UNLOCK_COND_TIMELOCK:
      return cond_timelock_serialize((unlock_cond_timelock_t*)blk->block, buf + offset, buf_len - offset);
    case UNLOCK_COND_EXPIRATION:
      return cond_expir_serialize((unlock_cond_expir_t*)blk->block, buf + offset, buf_len - offset);
    default:
      printf("[%s:%d] invalid condition block\n", __func__, __LINE__);
      break;
  }
  return offset;
}

unlock_cond_block_t* cond_blk_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_cond_block_t* blk = malloc(sizeof(unlock_cond_block_t));
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

void free_cond_blk(unlock_cond_block_t* blk) {
  if (blk) {
    switch (blk->type) {
      case UNLOCK_COND_ADDRESS:
      case UNLOCK_COND_STATE:
      case UNLOCK_COND_GOVERNOR:
        free_address((address_t*)blk->block);
        free(blk);
        break;
      case UNLOCK_COND_DUST:
        free_cond_dust((unlock_cond_dust_t*)blk->block);
        break;
      case UNLOCK_COND_TIMELOCK:
        free_cond_timelock((unlock_cond_timelock_t*)blk->block);
        break;
      case UNLOCK_COND_EXPIRATION:
        free_cond_expir((unlock_cond_expir_t*)blk->block);
        break;
    }
  }
}
