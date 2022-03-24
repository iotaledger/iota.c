// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/unlock_blocks.h"
#include "core/address.h"
#include "core/utils/macros.h"
#include "utlist.h"

static int unlock_block_signature_deserialize(cJSON *elm, unlock_list_t **unlock_blocks) {
  if (elm == NULL || unlock_blocks == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // signature array
  cJSON *sig_obj = cJSON_GetObjectItemCaseSensitive(elm, JSON_KEY_SIG);
  if (!cJSON_IsObject(sig_obj)) {
    printf("[%s:%d]: %s is not an object\n", __func__, __LINE__, JSON_KEY_SIG);
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
      byte_t sig_block[ED25519_SIGNATURE_BLOCK_BYTES] = {};
      sig_block[0] = 0;  // denote ed25519 signature
      // public key
      if (json_get_hex_str_to_bin(sig_obj, JSON_KEY_PUB_KEY, sig_block + 1, ED_PUBLIC_KEY_BYTES) != JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_PUB_KEY);
        return -1;
      }
      // signature
      if (json_get_hex_str_to_bin(sig_obj, JSON_KEY_SIG, sig_block + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES) !=
          JSON_OK) {
        printf("[%s:%d]: getting %s json string failed\n", __func__, __LINE__, JSON_KEY_SIG);
        return -1;
      }

      // add signature block into a list
      if (unlock_blocks_add_signature(unlock_blocks, sig_block, ED25519_SIGNATURE_BLOCK_BYTES) != 0) {
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

static cJSON *unlock_block_signature_serialize(unlock_block_t const *block) {
  cJSON *blk_obj = cJSON_CreateObject();
  cJSON *sig = NULL;
  if (blk_obj) {
    // add block type
    if (cJSON_AddNumberToObject(blk_obj, JSON_KEY_TYPE, block->type) == NULL) {
      printf("[%s:%d]: add type to json failed\n", __func__, __LINE__);
      goto err;
    }

    // create signature object
    sig = cJSON_CreateObject();
    if (sig) {
      // add signature object to block
      if (!cJSON_AddItemToObject(blk_obj, JSON_KEY_SIG, sig)) {
        cJSON_Delete(sig);
        goto err;
      }

      // block data: sig type + public key + signature
      uint8_t sig_type = ((uint8_t *)block->block_data)[0];
      if (sig_type != 0) {
        printf("[%s:%d]: unsupported signature type\n", __func__, __LINE__);
        goto err;
      }

      // add signature type
      if (cJSON_AddNumberToObject(sig, JSON_KEY_TYPE, sig_type) == NULL) {
        printf("[%s:%d]: add type to json failed\n", __func__, __LINE__);
        goto err;
      }

      // buffer to hold public and signature string
      char str_tmp[BIN_TO_HEX_STR_BYTES(ED_PRIVATE_KEY_BYTES) + JSON_HEX_ENCODED_STRING_PREFIX_LEN] = {};
      memcpy(str_tmp, "0x", JSON_HEX_ENCODED_STRING_PREFIX_LEN);

      // add public key
      if (bin_2_hex(block->block_data + 1, ED_PUBLIC_KEY_BYTES, str_tmp + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                    sizeof(str_tmp) - JSON_HEX_ENCODED_STRING_PREFIX_LEN) == 0) {
        if (cJSON_AddStringToObject(sig, JSON_KEY_PUB_KEY, str_tmp) == NULL) {
          printf("[%s:%d]: add public key to json failed\n", __func__, __LINE__);
          goto err;
        }
      } else {
        printf("[%s:%d]: converting pub key error\n", __func__, __LINE__);
        goto err;
      }

      // add signature
      if (bin_2_hex(block->block_data + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES,
                    str_tmp + JSON_HEX_ENCODED_STRING_PREFIX_LEN,
                    sizeof(str_tmp) - JSON_HEX_ENCODED_STRING_PREFIX_LEN) == 0) {
        if (cJSON_AddStringToObject(sig, JSON_KEY_SIG, str_tmp) == NULL) {
          printf("[%s:%d]: add signature to json failed\n", __func__, __LINE__);
          goto err;
        }
      } else {
        printf("[%s:%d]: converting signature error\n", __func__, __LINE__);
        goto err;
      }
    }
  }
  return blk_obj;

err:
  cJSON_Delete(blk_obj);
  return NULL;
}

static int unlock_block_reference_deserialize(cJSON *elm, unlock_list_t **unlock_blocks) {
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
  if (unlock_blocks_add_reference(unlock_blocks, reference) != 0) {
    printf("[%s:%d] can not add reference unlock block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static cJSON *unlock_block_reference_serialize(unlock_block_t const *const block) {
  cJSON *blk_obj = cJSON_CreateObject();

  if (blk_obj) {
    // add block type
    if (cJSON_AddNumberToObject(blk_obj, JSON_KEY_TYPE, block->type) == NULL) {
      printf("[%s:%d]: add type to json failed\n", __func__, __LINE__);
      goto err;
    }

    // add reference
    if (cJSON_AddNumberToObject(blk_obj, JSON_KEY_REFERENCE, *(uint16_t *)block->block_data) == NULL) {
      printf("[%s:%d]: add type to json failed\n", __func__, __LINE__);
      goto err;
    }
  }
  return blk_obj;

err:
  cJSON_Delete(blk_obj);
  return NULL;
}

static int unlock_block_alias_deserialize(cJSON *elm, unlock_list_t **unlock_blocks) {
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
  if (unlock_blocks_add_alias(unlock_blocks, reference) != 0) {
    printf("[%s:%d] can not add alias unlock block into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static int unlock_block_nft_deserialize(cJSON *elm, unlock_list_t **unlock_blocks) {
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
  if (unlock_blocks_add_nft(unlock_blocks, reference) != 0) {
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
        "publicKey": "0xdd2fb44b9809782af5f31fdbf767a39303365449308f78d6c2652ac9766dbf1a",
        "signature":
  "0xe625a71351bbccf87eeaad7e98f6a545306423b2aaf444792a1be8ccfdfe50b358583483c3dbc536b5842eeec381750c6b4495c14932be47c439a1a8ad242606"
      }
    },
  ]
*/
int json_unlock_blocks_deserialize(cJSON *blocks_obj, unlock_list_t **unlock_blocks) {
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

cJSON *json_unlock_blocks_serialize(unlock_list_t *blocks) {
  cJSON *unlock_arr = cJSON_CreateArray();
  if (unlock_arr) {
    // empty list
    if (!blocks) {
      return unlock_arr;
    }

    cJSON *item = NULL;
    unlock_list_t *elm;
    LL_FOREACH(blocks, elm) {
      switch (elm->block.type) {
        case UNLOCK_BLOCK_TYPE_SIGNATURE:
          item = unlock_block_signature_serialize(&elm->block);
          break;
        case UNLOCK_BLOCK_TYPE_REFERENCE:
          item = unlock_block_reference_serialize(&elm->block);
          break;
        case UNLOCK_BLOCK_TYPE_ALIAS:
        case UNLOCK_BLOCK_TYPE_NFT:
          printf("[%s:%d] TODO \n", __func__, __LINE__);
          break;
        default:
          break;
      }

      if (item) {
        // add item to array
        if (!cJSON_AddItemToArray(unlock_arr, item)) {
          printf("[%s:%d] add block to array error\n", __func__, __LINE__);
          cJSON_Delete(item);
          cJSON_Delete(unlock_arr);
          return NULL;
        }
      } else {
        printf("[%s:%d] serialize feature block error\n", __func__, __LINE__);
        cJSON_Delete(unlock_arr);
        return NULL;
      }
    }
  }

  return unlock_arr;
}
