// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/message.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "core/utils/macros.h"

static const UT_icd ut_blk_id_icd = {sizeof(uint8_t) * IOTA_BLOCK_ID_BYTES, NULL, NULL, NULL};

core_block_t* core_block_new(uint8_t ver) {
  core_block_t* blk = malloc(sizeof(core_block_t));
  if (blk) {
    blk->protocol_version = ver;
    utarray_new(blk->parents, &ut_blk_id_icd);
    blk->payload_type = CORE_BLOCK_PAYLOAD_UNKNOWN;  // invalid payload type
    blk->payload = NULL;
    blk->nonce = 0;
  }
  return blk;
}

int core_block_essence_hash_calc(core_block_t* blk, byte_t essence_hash[], uint8_t essence_hash_len) {
  if (blk == NULL || essence_hash == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (blk->payload_type != CORE_BLOCK_PAYLOAD_TRANSACTION || blk->payload == NULL) {
    printf("[%s:%d] invalid payload\n", __func__, __LINE__);
    return -1;
  }

  if (essence_hash_len < CRYPTO_BLAKE2B_256_HASH_BYTES) {
    printf("[%s:%d] essence hash array length is too small\n", __func__, __LINE__);
    return -1;
  }

  transaction_payload_t* tx = (transaction_payload_t*)blk->payload;

  // serialize transaction essence
  size_t essence_len = tx_essence_serialize_length(tx->essence);
  byte_t* b_essence = malloc(essence_len);
  if (!b_essence) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  size_t serialized_size = tx_essence_serialize(tx->essence, b_essence, essence_len);
  if (serialized_size != essence_len) {
    printf("[%s:%d] serialize length miss match\n", __func__, __LINE__);
    free(b_essence);
    return -1;
  }

  // calculate essence hash
  if (iota_blake2b_sum(b_essence, serialized_size, essence_hash, CRYPTO_BLAKE2B_256_HASH_BYTES) != 0) {
    printf("[%s:%d] get essence hash failed\n", __func__, __LINE__);
    free(b_essence);
    return -1;
  }

  // Clean up
  free(b_essence);

  return 0;
}

void core_block_free(core_block_t* blk) {
  if (blk) {
    if (blk->payload) {
      if (blk->payload_type == CORE_BLOCK_PAYLOAD_TRANSACTION) {
        tx_payload_free((transaction_payload_t*)blk->payload);
      } else if (blk->payload_type == CORE_BLOCK_PAYLOAD_MILESTONE) {
        milestone_payload_free((milestone_payload_t*)blk->payload);
      } else if (blk->payload_type == CORE_BLOCK_PAYLOAD_TAGGED) {
        tagged_data_free((tagged_data_payload_t*)blk->payload);
      } else {
        printf("[%s:%d] unsupported payload type\n", __func__, __LINE__);
      }
    }
    utarray_free(blk->parents);
    free(blk);
  }
}

void core_block_add_parent(core_block_t* blk, byte_t const blk_id[]) {
  if (blk) {
    utarray_push_back(blk->parents, blk_id);
  }
}

size_t core_block_parent_len(core_block_t* blk) {
  if (blk) {
    return utarray_len(blk->parents);
  }
  return 0;
}

byte_t* core_block_get_parent_id(core_block_t* blk, size_t index) {
  if (blk) {
    if (blk->parents && (index < core_block_parent_len(blk))) {
      return utarray_eltptr(blk->parents, index);
    }
  }
  return NULL;
}

core_block_payload_type_t core_block_get_payload_type(core_block_t* blk) {
  if (blk) {
    return blk->payload_type;
  }
  return CORE_BLOCK_PAYLOAD_UNKNOWN;
}

size_t core_block_serialize_len(core_block_t* blk) {
  if (blk == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t length = 0;

  // protocol version
  length += sizeof(uint8_t);
  // parents count
  length += sizeof(uint8_t);
  // parents
  length += core_block_parent_len(blk) * IOTA_BLOCK_ID_BYTES;
  // payload length
  length += sizeof(uint32_t);

  // payload
  switch (blk->payload_type) {
    case CORE_BLOCK_PAYLOAD_TRANSACTION:
      length += tx_payload_serialize_length((transaction_payload_t*)blk->payload);
      break;
    case CORE_BLOCK_PAYLOAD_TAGGED:
      length += tagged_data_serialize_len((tagged_data_payload_t*)(blk->payload));
      break;
    case CORE_BLOCK_PAYLOAD_MILESTONE:
    case CORE_BLOCK_PAYLOAD_INDEXATION:
    case CORE_BLOCK_PAYLOAD_RECEIPT:
    case CORE_BLOCK_PAYLOAD_TREASURY:
    case CORE_BLOCK_PAYLOAD_DEPRECATED_0:
    case CORE_BLOCK_PAYLOAD_DEPRECATED_1:
    default:
      printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
      return 0;
  }

  // nonce
  length += sizeof(uint64_t);

  return length;
}

size_t core_block_serialize(core_block_t* blk, byte_t buf[], size_t buf_len) {
  if (blk == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = core_block_serialize_len(blk);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;

  // protocol version
  memcpy(buf, &blk->protocol_version, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // parents count
  uint8_t parents_len = (uint8_t)core_block_parent_len(blk);
  memset(buf + offset, parents_len, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // parents
  for (uint8_t index = 0; index < parents_len; index++) {
    byte_t* parent_id = core_block_get_parent_id(blk, index);
    memcpy(buf + offset, parent_id, IOTA_BLOCK_ID_BYTES);
    offset += IOTA_BLOCK_ID_BYTES;
  }

  // payload length
  uint32_t payload_len = 0;
  switch (blk->payload_type) {
    case CORE_BLOCK_PAYLOAD_TRANSACTION:
      payload_len = (uint32_t)tx_payload_serialize_length((transaction_payload_t*)blk->payload);
      break;
    case CORE_BLOCK_PAYLOAD_TAGGED:
      payload_len = (uint32_t)tagged_data_serialize_len((tagged_data_payload_t*)(blk->payload));
      break;
    case CORE_BLOCK_PAYLOAD_MILESTONE:
    case CORE_BLOCK_PAYLOAD_INDEXATION:
    case CORE_BLOCK_PAYLOAD_RECEIPT:
    case CORE_BLOCK_PAYLOAD_TREASURY:
    case CORE_BLOCK_PAYLOAD_DEPRECATED_0:
    case CORE_BLOCK_PAYLOAD_DEPRECATED_1:
    default:
      printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
      return 0;
  }
  memcpy(buf + offset, &payload_len, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // payload
  switch (blk->payload_type) {
    case CORE_BLOCK_PAYLOAD_TRANSACTION:
      offset += tx_payload_serialize((transaction_payload_t*)blk->payload, buf + offset, buf_len - offset);
      break;
    case CORE_BLOCK_PAYLOAD_TAGGED:
      offset += tagged_data_serialize((tagged_data_payload_t*)blk->payload, buf + offset, buf_len - offset);
      break;
    case CORE_BLOCK_PAYLOAD_MILESTONE:
    case CORE_BLOCK_PAYLOAD_INDEXATION:
    case CORE_BLOCK_PAYLOAD_RECEIPT:
    case CORE_BLOCK_PAYLOAD_TREASURY:
    case CORE_BLOCK_PAYLOAD_DEPRECATED_0:
    case CORE_BLOCK_PAYLOAD_DEPRECATED_1:
    default:
      printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
      return 0;
  }

  // nonce
  memcpy(buf + offset, &blk->nonce, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  return offset;
}

void core_block_print(core_block_t* blk, uint8_t indentation) {
  printf("%sBlock: [\n", PRINT_INDENTATION(indentation));

  if (blk) {
    printf("%sProtocol Version: %d\n", PRINT_INDENTATION(indentation + 1), blk->protocol_version);

    printf("%sParent Block Ids:\n", PRINT_INDENTATION(indentation + 1));
    size_t parent_block_len = core_block_parent_len(blk);
    printf("%s\tParent Block Count: %lu\n", PRINT_INDENTATION(indentation + 1), parent_block_len);
    for (size_t index = 0; index < parent_block_len; index++) {
      printf("%s\t#%lu ", PRINT_INDENTATION(indentation + 1), index);
      dump_hex_str(core_block_get_parent_id(blk, index), IOTA_BLOCK_ID_BYTES);
    }

    switch (blk->payload_type) {
      case CORE_BLOCK_PAYLOAD_TRANSACTION:
        tx_payload_print((transaction_payload_t*)blk->payload, indentation + 1);
        break;
      case CORE_BLOCK_PAYLOAD_MILESTONE:
        milestone_payload_print((milestone_payload_t*)blk->payload, indentation + 1);
        break;
      case CORE_BLOCK_PAYLOAD_TAGGED:
        tagged_data_print((tagged_data_payload_t*)blk->payload, indentation + 1);
        break;
      case CORE_BLOCK_PAYLOAD_INDEXATION:
      case CORE_BLOCK_PAYLOAD_RECEIPT:
      case CORE_BLOCK_PAYLOAD_TREASURY:
      case CORE_BLOCK_PAYLOAD_DEPRECATED_0:
      case CORE_BLOCK_PAYLOAD_DEPRECATED_1:
      default:
        printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
        break;
    }

    printf("%sNonce: %" PRIu64 "\n", PRINT_INDENTATION(indentation + 1), blk->nonce);
  }

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
