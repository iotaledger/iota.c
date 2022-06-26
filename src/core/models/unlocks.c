// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/constants.h"
#include "core/models/unlocks.h"
#include "core/utils/macros.h"
#include "utlist.h"

// Maximum Unlock Count == Maximum Input Count
#define UNLOCKS_MAX_COUNT 128

unlock_list_t* unlock_list_new() { return NULL; }

int unlock_list_add(unlock_list_t** list, unlock_t* unlock) {
  if (unlock->type == UNLOCK_SIGNATURE_TYPE) {
    // Signature unlock must be unique. There must not be any other signature unlocks in unlock list with the same
    // signature.
    unlock_list_t* elm = NULL;
    LL_FOREACH(*list, elm) {
      if (elm->current.type == UNLOCK_SIGNATURE_TYPE) {
        if (memcmp(unlock->obj, elm->current.obj, sizeof(ED25519_SIGNATURE_BLOCK_BYTES)) == 0) {
          printf("[%s:%d] duplicated signature\n", __func__, __LINE__);
          return -1;
        }
      }
    }
  } else if (unlock->type == UNLOCK_REFERENCE_TYPE) {
    uint16_t count = unlock_list_count(*list);
    // Reference unlock at index i must have index < i
    if (*((uint16_t*)unlock->obj) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
    //  Unlock at index must be a signature unlock
    unlock_list_t* elm = *list;
    uint16_t index = 0;
    while (index < *((uint16_t*)unlock->obj)) {
      elm = elm->next;
      index++;
    }
    if (elm->current.type != UNLOCK_SIGNATURE_TYPE) {
      printf("[%s:%d] unlock type must be signature\n", __func__, __LINE__);
      return -1;
    }
  } else if (unlock->type == UNLOCK_ALIAS_TYPE) {
    uint16_t count = unlock_list_count(*list);
    // Alias unlock at index i must have index < i
    if (*((uint16_t*)unlock->obj) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
  } else if (unlock->type == UNLOCK_NFT_TYPE) {
    uint16_t count = unlock_list_count(*list);
    // NFT unlock at index i must have index < i
    if (*((uint16_t*)unlock->obj) >= count) {
      printf("[%s:%d] index too big\n", __func__, __LINE__);
      return -1;
    }
  }

  unlock_list_t* b = malloc(sizeof(unlock_list_t));
  if (b == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  memcpy(&b->current, unlock, sizeof(unlock_t));
  b->next = NULL;

  LL_APPEND(*list, b);
  return 0;
}

int unlock_list_add_signature(unlock_list_t** list, byte_t* sig, size_t sig_len) {
  if (sig == NULL || sig_len != ED25519_SIGNATURE_BLOCK_BYTES) {
    printf("[%s:%d] invalid signature\n", __func__, __LINE__);
    return -1;
  }

  unlock_t b;
  b.type = UNLOCK_SIGNATURE_TYPE;  // Signature unlock
  b.obj = malloc(ED25519_SIGNATURE_BLOCK_BYTES);
  if (b.obj == NULL) {
    printf("[%s:%d] allocate signature unlock failed\n", __func__, __LINE__);
    return -1;
  }

  memcpy(b.obj, sig, ED25519_SIGNATURE_BLOCK_BYTES);

  if (unlock_list_add(list, &b) == -1) {
    free(b.obj);
    return -1;
  }
  return 0;
}

int unlock_list_add_reference(unlock_list_t** list, uint16_t index) {
  // Reference Index must be 0 <= x < 128.
  if (index >= UNLOCKS_MAX_COUNT) {
    printf("[%s:%d] invalid Reference Index\n", __func__, __LINE__);
    return -1;
  }

  unlock_t b;
  b.type = UNLOCK_REFERENCE_TYPE;  // Reference unlock
  b.obj = malloc(sizeof(uint16_t));
  if (b.obj == NULL) {
    printf("[%s:%d] allocate reference unlock failed\n", __func__, __LINE__);
    return -1;
  }

  *(uint16_t*)b.obj = index;

  if (unlock_list_add(list, &b) == -1) {
    free(b.obj);
    return -1;
  }
  return 0;
}

int unlock_list_add_alias(unlock_list_t** list, uint16_t index) {
  // Alias Reference Index must be 0 <= x < 128.
  if (index >= UNLOCKS_MAX_COUNT) {
    printf("[%s:%d] index out of range \n", __func__, __LINE__);
    return -1;
  }

  unlock_t b;
  b.type = UNLOCK_ALIAS_TYPE;  // Alias unlock
  b.obj = malloc(sizeof(uint16_t));
  if (b.obj == NULL) {
    printf("[%s:%d] allocate alias unlock failed\n", __func__, __LINE__);
    return -1;
  }

  *(uint16_t*)b.obj = index;

  if (unlock_list_add(list, &b) == -1) {
    free(b.obj);
    return -1;
  }
  return 0;
}

int unlock_list_add_nft(unlock_list_t** list, uint16_t index) {
  // NFT Reference Index must be 0 <= x < 128.
  if (index >= UNLOCKS_MAX_COUNT) {
    printf("[%s:%d] index out of range \n", __func__, __LINE__);
    return -1;
  }

  unlock_t b;
  b.type = UNLOCK_NFT_TYPE;  // NFT unlock
  b.obj = malloc(sizeof(uint16_t));
  if (b.obj == NULL) {
    printf("[%s:%d] allocate NFT unlock failed\n", __func__, __LINE__);
    return -1;
  }

  *(uint16_t*)b.obj = index;

  if (unlock_list_add(list, &b) == -1) {
    free(b.obj);
    return -1;
  }
  return 0;
}

size_t unlock_list_serialize_length(unlock_list_t* list) {
  unlock_list_t* elm = NULL;
  size_t serialized_size = 0;

  // empty unlock
  if (list == NULL) {
    return 0;
  }

  // bytes of Unlocks Count
  serialized_size += sizeof(uint16_t);
  // calculate serialized bytes of unlocks
  LL_FOREACH(list, elm) {
    if (elm->current.type == UNLOCK_SIGNATURE_TYPE) {
      serialized_size += UNLOCK_SIGNATURE_SERIALIZE_BYTES;
    } else if (elm->current.type == UNLOCK_REFERENCE_TYPE) {
      serialized_size += UNLOCK_REFERENCE_SERIALIZE_BYTES;
    } else if (elm->current.type == UNLOCK_ALIAS_TYPE) {
      serialized_size += UNLOCK_ALIAS_SERIALIZE_BYTES;
    } else if (elm->current.type == UNLOCK_NFT_TYPE) {
      serialized_size += UNLOCK_NFT_SERIALIZE_BYTES;
    } else {
      printf("[%s:%d] Unknown unlock type\n", __func__, __LINE__);
      return 0;
    }
  }
  return serialized_size;
}

size_t unlock_list_serialize(unlock_list_t* list, byte_t buf[]) {
  unlock_list_t* elm = NULL;
  byte_t* offset = buf;

  uint16_t unlock_count = unlock_list_count(list);

  // unlock count
  memcpy(offset, &unlock_count, sizeof(unlock_count));
  offset += sizeof(unlock_count);

  // serializing unlocks
  LL_FOREACH(list, elm) {
    if (elm->current.type == UNLOCK_SIGNATURE_TYPE) {  // signature unlock
      memcpy(offset, &elm->current.type, sizeof(byte_t));
      offset += sizeof(byte_t);
      memcpy(offset, elm->current.obj, ED25519_SIGNATURE_BLOCK_BYTES);
      offset += ED25519_SIGNATURE_BLOCK_BYTES;
    } else if ((elm->current.type == UNLOCK_REFERENCE_TYPE) || (elm->current.type == UNLOCK_ALIAS_TYPE) ||
               (elm->current.type == UNLOCK_NFT_TYPE)) {  // reference, alias or NFT unlock
      memcpy(offset, &elm->current.type, sizeof(byte_t));
      offset += sizeof(byte_t);
      memcpy(offset, elm->current.obj, sizeof(uint16_t));
      offset += sizeof(uint16_t);
    }
  }

  return (size_t)(offset - buf) / sizeof(byte_t);
}

unlock_list_t* unlock_list_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len < 2) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  unlock_list_t* list = unlock_list_new();

  uint16_t list_count;
  memcpy(&list_count, &buf[0], sizeof(list_count));
  size_t offset = sizeof(uint16_t);

  if (list_count == 0) {
    return list;
  }

  for (uint16_t i = 0; i < list_count; i++) {
    // unlock type
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      unlock_list_free(list);
      return NULL;
    }
    uint8_t unlock_type;
    memcpy(&unlock_type, &buf[offset], sizeof(uint8_t));
    offset += sizeof(uint8_t);

    switch (unlock_type) {
      case UNLOCK_SIGNATURE_TYPE: {
        // ed25519 signature
        if (buf_len < offset + ED25519_SIGNATURE_BLOCK_BYTES) {
          printf("[%s:%d] invalid data length\n", __func__, __LINE__);
          unlock_list_free(list);
          return NULL;
        }
        byte_t signature_unlock[ED25519_SIGNATURE_BLOCK_BYTES];
        memcpy(signature_unlock, &buf[offset], sizeof(signature_unlock));
        offset += sizeof(signature_unlock);

        if (unlock_list_add_signature(&list, signature_unlock, sizeof(signature_unlock)) != 0) {
          printf("[%s:%d] can not add unlock to the list\n", __func__, __LINE__);
          unlock_list_free(list);
          return NULL;
        }
        break;
      }
      case UNLOCK_REFERENCE_TYPE:
      case UNLOCK_ALIAS_TYPE:
      case UNLOCK_NFT_TYPE: {
        // index
        if (buf_len < offset + sizeof(uint16_t)) {
          printf("[%s:%d] invalid data length\n", __func__, __LINE__);
          unlock_list_free(list);
          return NULL;
        }
        uint16_t index;
        memcpy(&index, &buf[offset], sizeof(uint16_t));
        offset += sizeof(uint16_t);

        int result = -1;
        if (unlock_type == UNLOCK_REFERENCE_TYPE) {
          result = unlock_list_add_reference(&list, index);
        } else if (unlock_type == UNLOCK_ALIAS_TYPE) {
          result = unlock_list_add_alias(&list, index);
        } else if (unlock_type == UNLOCK_NFT_TYPE) {
          result = unlock_list_add_nft(&list, index);
        }
        if (result != 0) {
          printf("[%s:%d] can not add unlock to the list\n", __func__, __LINE__);
          unlock_list_free(list);
          return NULL;
        }
        break;
      }
      default:
        printf("[%s:%d] unknown unlock type\n", __func__, __LINE__);
        unlock_list_free(list);
        return NULL;
    }
  }

  return list;
}

unlock_t* unlock_list_get(unlock_list_t* list, uint16_t index) {
  if (!list) {
    return NULL;
  }
  uint16_t count = 0;
  unlock_list_t* elm;
  LL_FOREACH(list, elm) {
    if (count == index) {
      return &elm->current;
    }
    count++;
  }
  return NULL;
}

uint16_t unlock_list_count(unlock_list_t* list) {
  unlock_list_t* elm = NULL;
  uint16_t count = 0;
  if (list) {
    LL_COUNT(list, elm, count);
  }
  return count;
}

int32_t unlock_list_find_pub(unlock_list_t* list, byte_t const* const pub_key) {
  unlock_list_t* elm;
  int32_t count = 0;
  if (list) {
    LL_FOREACH(list, elm) {
      if (elm->current.type == UNLOCK_SIGNATURE_TYPE) {
        if (memcmp((byte_t*)elm->current.obj + 1, pub_key, ED_PUBLIC_KEY_BYTES) == 0) {
          return count;
        }
      }
      count++;
    }
  }
  return -1;
}

void unlock_list_free(unlock_list_t* list) {
  unlock_list_t *elm, *tmp;
  if (list) {
    LL_FOREACH_SAFE(list, elm, tmp) {
      if (elm->current.obj) {
        free(elm->current.obj);
      }
      LL_DELETE(list, elm);
      free(elm);
    }
  }
}

void unlock_list_print(unlock_list_t* list, uint8_t indentation) {
  unlock_list_t* elm;
  if (list) {
    printf("%sUnlocks: [\n", PRINT_INDENTATION(indentation));
    LL_FOREACH(list, elm) {
      if (elm->current.type == UNLOCK_SIGNATURE_TYPE) {  // signature unlock
        printf("%s\tSignature Unlock: [\n", PRINT_INDENTATION(indentation));
        printf("%s\t\tType: %s\n", PRINT_INDENTATION(indentation),
               ((byte_t*)elm->current.obj)[0] ? "UNKNOWN" : "ED25519");
        printf("%s\t\tPub key: ", PRINT_INDENTATION(indentation));
        dump_hex_str((const byte_t*)elm->current.obj + 1, ED_PUBLIC_KEY_BYTES);
        printf("%s\t\tSignature: ", PRINT_INDENTATION(indentation));
        dump_hex_str((const byte_t*)elm->current.obj + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES);
        printf("%s\t]\n", PRINT_INDENTATION(indentation));
      } else if (elm->current.type == UNLOCK_REFERENCE_TYPE) {  // reference unlock
        printf("%s\tReference Unlock[ ", PRINT_INDENTATION(indentation));
        printf("Ref: %" PRIu16 " ]\n", *(uint16_t*)elm->current.obj);
      } else if (elm->current.type == UNLOCK_ALIAS_TYPE) {  // alias unlock
        printf("%s\tAlias Unlock[ ", PRINT_INDENTATION(indentation));
        printf("Ref: %" PRIu16 " ]\n", *(uint16_t*)elm->current.obj);
      } else if (elm->current.type == UNLOCK_NFT_TYPE) {  // NFT unlock
        printf("%s\tNFT Unlock[ ", PRINT_INDENTATION(indentation));
        printf("Ref: %" PRIu16 " ]\n", *(uint16_t*)elm->current.obj);
      } else {
        printf("[%s:%d] Unknown unlock type\n", __func__, __LINE__);
      }
    }
    printf("%s]\n", PRINT_INDENTATION(indentation));
  }
}
