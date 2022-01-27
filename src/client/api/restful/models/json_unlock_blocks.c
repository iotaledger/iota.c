// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/models/json_unlock_blocks.h"

#define UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN 64
#define UNLOCK_BLOCKS_SIGN_HEX_STR_LEN 128
#define UNLOCK_BLOCKS_SIGN_BLOCK_STR_LEN (1 + UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN + UNLOCK_BLOCKS_SIGN_HEX_STR_LEN)

static int unlock_block_signature_deserialize(cJSON *elm, transaction_payload_t *payload_tx) {
  cJSON *sig_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_SIG);
  if (sig_obj) {
    cJSON *sig_type = cJSON_GetObjectItemCaseSensitive(sig_obj, JSON_KEY_TYPE);
    if (cJSON_IsNumber(sig_type)) {
      if (sig_type->valueint == ADDRESS_TYPE_ED25519) {
        cJSON *pub = cJSON_GetObjectItemCaseSensitive(sig_obj, JSON_KEY_PUB_KEY);
        cJSON *sig = cJSON_GetObjectItemCaseSensitive(sig_obj, JSON_KEY_SIG);
        if (cJSON_IsString(pub) && cJSON_IsString(sig)) {
          byte_t sig_block[UNLOCK_BLOCKS_SIGN_BLOCK_STR_LEN] = {};
          sig_block[0] = sig_type->valueint;
          memcpy(sig_block + 1, pub->valuestring, UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN);
          memcpy(sig_block + 1 + UNLOCK_BLOCKS_PUB_KEY_HEX_STR_LEN, sig->valuestring, UNLOCK_BLOCKS_SIGN_HEX_STR_LEN);
          if (unlock_blocks_add_signature(&payload_tx->unlock_blocks, sig_block, UNLOCK_BLOCKS_SIGN_BLOCK_STR_LEN) !=
              0) {
            printf("[%s:%d] can not add signature unlock block into a list\n", __func__, __LINE__);
            return -1;
          }
        } else {
          printf("[%s:%d] publicKey or signature is not a string\n", __func__, __LINE__);
          return -1;
        }
      } else {
        printf("[%s:%d] only suppport ed25519 signature\n", __func__, __LINE__);
        return -1;
      }
    } else {
      printf("[%s:%d] signature type is not an number\n", __func__, __LINE__);
      return -1;
    }
  } else {
    printf("[%s:%d] %s is not found\n", __func__, __LINE__, JSON_KEY_SIG);
    return -1;
  }
  return 0;
}

static int unlock_block_reference_deserialize(cJSON *elm, transaction_payload_t *payload_tx) {
  cJSON *ref = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_REFERENCE);
  if (!cJSON_IsNumber(ref)) {
    printf("[%s:%d]: %s is not a number object\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }
  if (unlock_blocks_add_reference(&payload_tx->unlock_blocks, ref->valueint) != 0) {
    printf("[%s:%d] can not add reference unlock block into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

static int unlock_block_alias_deserialize(cJSON *elm, transaction_payload_t *payload_tx) {
  cJSON *ref = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_REFERENCE);
  if (!cJSON_IsNumber(ref)) {
    printf("[%s:%d]: %s is not a number object\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }
  if (unlock_blocks_add_alias(&payload_tx->unlock_blocks, ref->valueint) != 0) {
    printf("[%s:%d] can not add alias unlock block into a list\n", __func__, __LINE__);
    return -1;
  }
  return 0;
}

static int unlock_block_nft_deserialize(cJSON *elm, transaction_payload_t *payload_tx) {
  cJSON *ref = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_REFERENCE);
  if (!cJSON_IsNumber(ref)) {
    printf("[%s:%d]: %s is not a number object\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }
  if (unlock_blocks_add_nft(&payload_tx->unlock_blocks, ref->valueint) != 0) {
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
int json_unlock_blocks_deserialize(cJSON *blocks_obj, transaction_payload_t *payload_tx) {
  if (blocks_obj == NULL || payload_tx == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, blocks_obj) {
    cJSON *block_type = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_TYPE);
    if (!cJSON_IsNumber(block_type)) {
      printf("[%s:%d] %s must be a number\n", __func__, __LINE__, JSON_KEY_TYPE);
      break;
    }

    switch (block_type->valueint) {
      case UNLOCK_BLOCK_TYPE_SIGNATURE:
        if (unlock_block_signature_deserialize(elm, payload_tx) != 0) {
          return -1;
        }
        break;
      case UNLOCK_BLOCK_TYPE_REFERENCE:
        if (unlock_block_reference_deserialize(elm, payload_tx) != 0) {
          return -1;
        }
        break;
      case UNLOCK_BLOCK_TYPE_ALIAS:
        if (unlock_block_alias_deserialize(elm, payload_tx) != 0) {
          return -1;
        }
        break;
      case UNLOCK_BLOCK_TYPE_NFT:
        if (unlock_block_nft_deserialize(elm, payload_tx) != 0) {
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
