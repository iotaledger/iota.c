// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/signing.h"
#include "utlist.h"

static int create_signature_ed25519_unlock(byte_t essence_hash[], signing_data_t* sign_data,
                                           unlock_list_t** unlock_list) {
  int32_t pub_index = unlock_list_find_pub(*unlock_list, sign_data->keypair->pub);
  if (pub_index == -1) {
    // public key is not found in the unlock list
    byte_t sig_unlock[ED25519_SIGNATURE_BLOCK_BYTES] = {0};
    sig_unlock[0] = ADDRESS_TYPE_ED25519;
    memcpy(sig_unlock + 1, sign_data->keypair->pub, ED_PUBLIC_KEY_BYTES);

    // sign transaction
    if (iota_crypto_sign(sign_data->keypair->priv, essence_hash, CRYPTO_BLAKE2B_256_HASH_BYTES,
                         sig_unlock + (1 + ED_PUBLIC_KEY_BYTES)) != 0) {
      printf("[%s:%d] signing signature failed\n", __func__, __LINE__);
      return -1;
    }

    // create a signature unlock
    if (unlock_list_add_signature(unlock_list, sig_unlock, ED25519_SIGNATURE_BLOCK_BYTES) != 0) {
      printf("[%s:%d] add signature unlock failed\n", __func__, __LINE__);
      return -1;
    }
  } else {
    // public key is found in the unlock list, just add a reference
    if (unlock_list_add_reference(unlock_list, (uint16_t)pub_index) != 0) {
      printf("[%s:%d] add reference unlock failed\n", __func__, __LINE__);
      return -1;
    }
  }

  return 0;
}

static int create_alias_or_nft_unlock(signing_data_t* sign_data, signing_data_list_t* signing_data_list,
                                      unlock_list_t** unlock_list) {
  signing_data_list_t* elm;
  uint8_t index = 0;
  if (signing_data_list) {
    LL_FOREACH(signing_data_list, elm) {
      if (memcmp(elm->sign_data->hash, sign_data->unlock_address.address, CRYPTO_BLAKE2B_256_HASH_BYTES) == 0) {
        if (sign_data->unlock_address.type == ADDRESS_TYPE_ALIAS) {
          if (unlock_list_add_alias(unlock_list, index) != 0) {
            printf("[%s:%d] adding Alias unlock failed\n", __func__, __LINE__);
            return -1;
          }
          return 0;
        } else if (sign_data->unlock_address.type == ADDRESS_TYPE_NFT) {
          if (unlock_list_add_nft(unlock_list, index) != 0) {
            printf("[%s:%d] adding NFT unlock failed\n", __func__, __LINE__);
            return -1;
          }
          return 0;
        } else {
          printf("[%s:%d] address in unlock must be Alias or NFT\n", __func__, __LINE__);
          return -1;
        }
      }
      index += 1;
    }
  }

  printf("[%s:%d] Alias or NFT address was not found in signing data list.\n", __func__, __LINE__);
  return -1;
}

signing_data_list_t* signing_new() { return NULL; }

void signing_free(signing_data_list_t* signing_data_list) {
  if (signing_data_list) {
    signing_data_list_t *elm, *tmp;
    LL_FOREACH_SAFE(signing_data_list, elm, tmp) {
      if (elm->sign_data->keypair) {
        free(elm->sign_data->keypair);
      }
      free(elm->sign_data);
      LL_DELETE(signing_data_list, elm);
      free(elm);
    }
  }
}

int signing_data_add(address_t* unlock_address, byte_t hash[], uint8_t hash_len, ed25519_keypair_t* keypair,
                     signing_data_list_t** sign_data_list) {
  if (unlock_address == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (hash != NULL && hash_len < CRYPTO_BLAKE2B_256_HASH_BYTES) {
    printf("[%s:%d] hash array length is too small\n", __func__, __LINE__);
    return -1;
  }

  signing_data_list_t* sign_data_next = malloc(sizeof(signing_data_t));
  if (!sign_data_next) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  signing_data_t* sign_data = malloc(sizeof(signing_data_t));
  if (!sign_data) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    free(sign_data_next);
    return -1;
  }
  memset(sign_data, 0, sizeof(signing_data_t));

  memcpy(&sign_data->unlock_address, unlock_address, sizeof(address_t));
  if (hash) {
    memcpy(sign_data->hash, hash, CRYPTO_BLAKE2B_256_HASH_BYTES);
  }
  if (keypair) {
    sign_data->keypair = malloc(sizeof(ed25519_keypair_t));
    memcpy(sign_data->keypair, keypair, sizeof(ed25519_keypair_t));
  }

  sign_data_next->sign_data = sign_data;
  sign_data_next->next = NULL;

  LL_APPEND(*sign_data_list, sign_data_next);

  return 0;
}

uint8_t signing_data_count(signing_data_list_t* signing_data_list) {
  signing_data_list_t* elm = NULL;
  uint16_t len = 0;
  if (signing_data_list) {
    LL_COUNT(signing_data_list, elm, len);
  }
  return len;
}

signing_data_t* signing_get_data_by_index(signing_data_list_t* signing_data_list, uint8_t index) {
  if (signing_data_list == NULL) {
    printf("[%s:%d] empty signing data list\n", __func__, __LINE__);
    return NULL;
  }

  if (index >= UTXO_INPUT_MAX_COUNT) {
    printf("[%s:%d] invalid index\n", __func__, __LINE__);
    return NULL;
  }

  signing_data_list_t* elm;
  uint8_t curr_index = 0;
  if (signing_data_list) {
    LL_FOREACH(signing_data_list, elm) {
      if (curr_index == index) {
        return elm->sign_data;
      }
      curr_index++;
    }
  }
  return NULL;
}

int signing_transaction_sign(byte_t essence_hash[], uint8_t essence_hash_len, utxo_inputs_list_t* inputs,
                             signing_data_list_t* sign_data_list, unlock_list_t** unlock_list) {
  if (essence_hash == NULL || inputs == NULL || sign_data_list == NULL || *unlock_list != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (utxo_inputs_count(inputs) != signing_data_count(sign_data_list)) {
    printf("[%s:%d] number of inputs and signing data in a lists are not the same\n", __func__, __LINE__);
    return -1;
  }

  if (essence_hash_len < CRYPTO_BLAKE2B_256_HASH_BYTES) {
    printf("[%s:%d] essence hash array length is too small\n", __func__, __LINE__);
    return -1;
  }

  uint8_t index = 0;
  utxo_inputs_list_t* elm;
  LL_FOREACH(inputs, elm) {
    signing_data_t* sign_data = signing_get_data_by_index(sign_data_list, index);

    if (sign_data->keypair) {
      if (create_signature_ed25519_unlock(essence_hash, sign_data, unlock_list) != 0) {
        printf("[%s:%d] creating unlock for ed25519 address failed.\n", __func__, __LINE__);
        return -1;
      }
    } else {
      if (create_alias_or_nft_unlock(sign_data, sign_data_list, unlock_list) != 0) {
        printf("[%s:%d] creating unlock for Alias or NFT address failed.\n", __func__, __LINE__);
        return -1;
      }
    }

    index += 1;
  }

  return 0;
}
