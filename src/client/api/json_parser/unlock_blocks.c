// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/unlock_blocks.h"

#define UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN 64
#define UNLOCK_BLOCKS_SIGN_HEX_STR_LEN 128
#define UNLOCK_BLOCKS_SIGN_BLOCK_STR_LEN (1 + UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN + UNLOCK_BLOCKS_SIGN_HEX_STR_LEN)

static int unlock_block_signature_deserialize(cJSON *elm, unlock_list_t *unlock_blocks) {
  if (elm == NULL || unlock_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // signature array
  cJSON *sig_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_SIG);
  if (!cJSON_IsArray(sig_obj)) {
    printf("[%s:%d]: %s is not an array\n", __func__, __LINE__, JSON_KEY_SIG);
    return -1;
  }

  // type
  uint8_t sig_type;
  if (json_get_uint8(sig_obj, JSON_KEY_TYPE, &sig_type) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
    return -1;
  }

  switch (sig_type) {
    case ADDRESS_TYPE_ED25519: {
      // public key
      char pub_key[UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN];
      if (json_get_string(sig_obj, JSON_KEY_PUB_KEY, pub_key, UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN) != JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_PUB_KEY);
        return -1;
      }
      // signature
      char signature[UNLOCK_BLOCKS_SIGN_HEX_STR_LEN];
      if (json_get_string(sig_obj, JSON_KEY_SIG, signature, UNLOCK_BLOCKS_SIGN_HEX_STR_LEN) != JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_SIG);
        return -1;
      }
      byte_t sig_block[UNLOCK_BLOCKS_SIGN_BLOCK_STR_LEN] = {};
      sig_block[0] = sig_type;
      memcpy(sig_block + 1, pub_key, UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN);
      memcpy(sig_block + 1 + UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN, signature, UNLOCK_BLOCKS_SIGN_HEX_STR_LEN);

      // add signature block into a list
      if (unlock_blocks_add_signature(&unlock_blocks, sig_block, UNLOCK_BLOCKS_SIGN_BLOCK_STR_LEN) != 0) {
        printf("[%s:%d] can not add signature unlock block into a list\n", __func__, __LINE__);
        return -1;
      }
    }
    case ADDRESS_TYPE_ALIAS:
      // TODO support alias address type
      break;
    case ADDRESS_TYPE_NFT:
      // TODO support NFT address type
      break;
    default:
      printf("[%s:%d] unsupported address type\n", __func__, __LINE__);
      return -1;
  }

  return 0;
}

static int unlock_block_reference_deserialize(cJSON *elm, unlock_list_t *unlock_blocks) {
  if (elm == NULL || unlock_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // reference
  uint16_t reference;
  if (json_get_uint16(elm, JSON_KEY_REFERENCE, &reference) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }

  // add new unlock block into a list
  if (unlock_blocks_add_reference(&unlock_blocks, reference) != 0) {
    printf("[%s:%d] can not add reference unlock block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static int unlock_block_alias_deserialize(cJSON *elm, unlock_list_t *unlock_blocks) {
  if (elm == NULL || unlock_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // reference
  uint16_t reference;
  if (json_get_uint16(elm, JSON_KEY_REFERENCE, &reference) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }

  // add new unlock block into a list
  if (unlock_blocks_add_alias(&unlock_blocks, reference) != 0) {
    printf("[%s:%d] can not add alias unlock block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static int unlock_block_nft_deserialize(cJSON *elm, unlock_list_t *unlock_blocks) {
  if (elm == NULL || unlock_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // reference
  uint16_t reference;
  if (json_get_uint16(elm, JSON_KEY_REFERENCE, &reference) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }

  // add new unlock block into a list
  if (unlock_blocks_add_nft(&unlock_blocks, reference) != 0) {
    printf("[%s:%d] can not add NFT unlock block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

/*
  "unlockBlocks": [
    { "type": 0,
      "signature": {
        "type": 1,
        "publicKey": "dd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a",
        "signature":
  "e625a71351bbccf87eeaad7e98f6a545306423b2aaf444792a1be8ccfdfe50b358583483c3dbc536b5842eeec381750c6b4495c14932be47c439a1a8ad242606"
      }
    },
  ]
*/
int json_unlock_blocks_deserialize(cJSON *blocks_obj, unlock_list_t *unlock_blocks) {
  if (blocks_obj == NULL || unlock_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, blocks_obj) {
    // type
    uint8_t block_type;
    if (json_get_uint8(elm, JSON_KEY_TYPE, &block_type) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // unlock block
    switch (block_type) {
      case UNLOCK_BLOCK_TYPE_SIGNATURE:
        if (unlock_block_signature_deserialize(elm, unlock_blocks) != 0) {
          return -1;
        }
        break;
      case UNLOCK_BLOCK_TYPE_REFERENCE:
        if (unlock_block_reference_deserialize(elm, unlock_blocks) != 0) {
          return -1;
        }
        break;
      case UNLOCK_BLOCK_TYPE_ALIAS:
        if (unlock_block_alias_deserialize(elm, unlock_blocks) != 0) {
          return -1;
        }
        break;
      case UNLOCK_BLOCK_TYPE_NFT:
        if (unlock_block_nft_deserialize(elm, unlock_blocks) != 0) {
          return -1;
        }
        break;
      default:
        printf("[%s:%d] unsupported unlock block type\n", __func__, __LINE__);
        return -1;
    }
  }

  return 0;
}
