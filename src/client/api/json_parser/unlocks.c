// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/json_parser/unlocks.h"
#include "core/address.h"
#include "core/models/unlocks.h"
#include "core/utils/macros.h"
#include "utlist.h"

static int unlock_signature_deserialize(cJSON *elm, unlock_list_t **unlock_list) {
  if (elm == NULL || unlock_list == NULL) {
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

      // add signature unlock into a list
      if (unlock_list_add_signature(unlock_list, sig_block, ED25519_SIGNATURE_BLOCK_BYTES) != 0) {
        printf("[%s:%d] can not add signature unlock into a list\n", __func__, __LINE__);
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

static cJSON *unlock_signature_serialize(unlock_t const *sig_unlock) {
  cJSON *blk_obj = cJSON_CreateObject();
  cJSON *sig = NULL;
  if (blk_obj) {
    // add unlock type
    if (cJSON_AddNumberToObject(blk_obj, JSON_KEY_TYPE, sig_unlock->type) == NULL) {
      printf("[%s:%d]: add type to json failed\n", __func__, __LINE__);
      goto err;
    }

    // create signature object
    sig = cJSON_CreateObject();
    if (sig) {
      // add signature object to unlock
      if (!cJSON_AddItemToObject(blk_obj, JSON_KEY_SIG, sig)) {
        cJSON_Delete(sig);
        goto err;
      }

      // signature data: sig type + public key + signature
      uint8_t sig_type = ((uint8_t *)sig_unlock->obj)[0];
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
      char str_tmp[JSON_STR_WITH_PREFIX_BYTES(ED_PRIVATE_KEY_BYTES)] = {};

      // add public key
      if (bin_2_hex(sig_unlock->obj + 1, ED_PUBLIC_KEY_BYTES, JSON_HEX_ENCODED_STRING_PREFIX, str_tmp,
                    sizeof(str_tmp)) == 0) {
        if (cJSON_AddStringToObject(sig, JSON_KEY_PUB_KEY, str_tmp) == NULL) {
          printf("[%s:%d]: add public key to json failed\n", __func__, __LINE__);
          goto err;
        }
      } else {
        printf("[%s:%d]: converting pub key error\n", __func__, __LINE__);
        goto err;
      }

      // add signature
      if (bin_2_hex(sig_unlock->obj + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES, JSON_HEX_ENCODED_STRING_PREFIX,
                    str_tmp, sizeof(str_tmp)) == 0) {
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

static int unlock_reference_deserialize(cJSON *elm, unlock_list_t **unlock_list) {
  if (elm == NULL || unlock_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // reference
  uint16_t reference;
  if (json_get_uint16(elm, JSON_KEY_REFERENCE, &reference) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }

  // add new unlock into a list
  if (unlock_list_add_reference(unlock_list, reference) != 0) {
    printf("[%s:%d] can not add reference unlock into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static cJSON *unlock_reference_serialize(unlock_t const *const ref_unlock) {
  cJSON *blk_obj = cJSON_CreateObject();

  if (blk_obj) {
    // add unlock type
    if (cJSON_AddNumberToObject(blk_obj, JSON_KEY_TYPE, ref_unlock->type) == NULL) {
      printf("[%s:%d]: add type to json failed\n", __func__, __LINE__);
      goto err;
    }

    // add reference
    if (cJSON_AddNumberToObject(blk_obj, JSON_KEY_REFERENCE, *(uint16_t *)ref_unlock->obj) == NULL) {
      printf("[%s:%d]: add type to json failed\n", __func__, __LINE__);
      goto err;
    }
  }
  return blk_obj;

err:
  cJSON_Delete(blk_obj);
  return NULL;
}

static int unlock_alias_deserialize(cJSON *elm, unlock_list_t **unlock_list) {
  if (elm == NULL || unlock_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // reference
  uint16_t reference;
  if (json_get_uint16(elm, JSON_KEY_REFERENCE, &reference) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }

  // add new unlock into a list
  if (unlock_list_add_alias(unlock_list, reference) != 0) {
    printf("[%s:%d] can not add alias unlock into a list\n", __func__, __LINE__);
    return -1;
  }

  return 0;
}

static int unlock_nft_deserialize(cJSON *elm, unlock_list_t **unlock_list) {
  if (elm == NULL || unlock_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // reference
  uint16_t reference;
  if (json_get_uint16(elm, JSON_KEY_REFERENCE, &reference) != JSON_OK) {
    printf("[%s:%d]: getting %s json uint16 failed\n", __func__, __LINE__, JSON_KEY_REFERENCE);
    return -1;
  }

  // add new unlock into a list
  if (unlock_list_add_nft(unlock_list, reference) != 0) {
    printf("[%s:%d] can not add NFT unlock into a list\n", __func__, __LINE__);
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
int json_unlocks_deserialize(cJSON *unlocks_obj, unlock_list_t **unlock_list) {
  if (unlocks_obj == NULL || unlock_list == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON *elm = NULL;
  cJSON_ArrayForEach(elm, unlocks_obj) {
    // type
    uint8_t unlock_type;
    if (json_get_uint8(elm, JSON_KEY_TYPE, &unlock_type) != JSON_OK) {
      printf("[%s:%d]: getting %s json uint8 failed\n", __func__, __LINE__, JSON_KEY_TYPE);
      return -1;
    }

    // unlock
    switch (unlock_type) {
      case UNLOCK_SIGNATURE_TYPE:
        if (unlock_signature_deserialize(elm, unlock_list) != 0) {
          return -1;
        }
        break;
      case UNLOCK_REFERENCE_TYPE:
        if (unlock_reference_deserialize(elm, unlock_list) != 0) {
          return -1;
        }
        break;
      case UNLOCK_ALIAS_TYPE:
        if (unlock_alias_deserialize(elm, unlock_list) != 0) {
          return -1;
        }
        break;
      case UNLOCK_NFT_TYPE:
        if (unlock_nft_deserialize(elm, unlock_list) != 0) {
          return -1;
        }
        break;
      default:
        printf("[%s:%d] unsupported unlock type\n", __func__, __LINE__);
        return -1;
    }
  }

  return 0;
}

cJSON *json_unlocks_serialize(unlock_list_t *unlock_list) {
  cJSON *unlock_arr = cJSON_CreateArray();
  if (unlock_arr) {
    // empty list
    if (!unlock_list) {
      return unlock_arr;
    }

    cJSON *item = NULL;
    unlock_list_t *elm;
    LL_FOREACH(unlock_list, elm) {
      switch (elm->current.type) {
        case UNLOCK_SIGNATURE_TYPE:
          item = unlock_signature_serialize(&elm->current);
          break;
        case UNLOCK_REFERENCE_TYPE:
          item = unlock_reference_serialize(&elm->current);
          break;
        case UNLOCK_ALIAS_TYPE:
        case UNLOCK_NFT_TYPE:
          printf("[%s:%d] TODO \n", __func__, __LINE__);
          break;
        default:
          break;
      }

      if (item) {
        // add item to array
        if (!cJSON_AddItemToArray(unlock_arr, item)) {
          printf("[%s:%d] add unlock to array error\n", __func__, __LINE__);
          cJSON_Delete(item);
          cJSON_Delete(unlock_arr);
          return NULL;
        }
      } else {
        printf("[%s:%d] serialize unlock error\n", __func__, __LINE__);
        cJSON_Delete(unlock_arr);
        return NULL;
      }
    }
  }

  return unlock_arr;
}
