// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>

#include "core/address.h"
#include "core/models/signing.h"
#include "utlist.h"

typedef struct {
  uint8_t index;      ///< Index in which position is pubKeyHash for NFT or Alias input in unlock block
  address_t address;  ///< NFT or Alias address
} unlock_block_index_t;

typedef struct unlock_block_list {
  unlock_block_index_t* unlock_block_index;  //< Points to a current unlock block index
  struct unlock_block_list* next;            //< Points to a next unlock block index
} unlock_block_index_list_t;

static void unlock_block_index_list_free(unlock_block_index_list_t* index_list) {
  if (index_list) {
    unlock_block_index_list_t *elm, *tmp;
    LL_FOREACH_SAFE(index_list, elm, tmp) {
      free(elm->unlock_block_index);
      LL_DELETE(index_list, elm);
      free(elm);
    }
  }
}

static int update_unlock_block_index(utxo_input_t* input, unlock_list_t* unlock_blocks,
                                     unlock_block_index_list_t** unlock_block_index_list) {
  if (input == NULL || unlock_blocks == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  unlock_block_index_list_t* new_index = malloc(sizeof(unlock_block_index_list_t));
  if (!new_index) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  new_index->unlock_block_index = malloc(sizeof(unlock_block_index_t));
  if (!new_index->unlock_block_index) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    free(new_index);
    return -1;
  }

  // add new unlock block index into a list
  /*new_index->unlock_block_index->index = unlock_blocks_find_pub(unlock_blocks, input->keypair->pub);
  memcpy(&new_index->unlock_block_index->address, input->address, sizeof(new_index->unlock_block_index->address));
  new_index->next = NULL;
  LL_APPEND(*unlock_block_index_list, new_index);*/

  return 0;
}

static int create_unlock_block_ed25519(utxo_input_t* input, byte_t essence_hash[],
                                       unlock_block_index_list_t** unlock_block_index_list,
                                       unlock_list_t** unlock_blocks) {
  if (input == NULL || essence_hash == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  int32_t pub_index = unlock_blocks_find_pub(*unlock_blocks, input->keypair->pub);
  if (pub_index == -1) {
    // public key is not found in the unlocked block
    byte_t sig_block[ED25519_SIGNATURE_BLOCK_BYTES] = {};
    sig_block[0] = ADDRESS_TYPE_ED25519;
    memcpy(sig_block + 1, input->keypair->pub, ED_PUBLIC_KEY_BYTES);

    // sign transaction
    if (iota_crypto_sign(input->keypair->priv, essence_hash, CRYPTO_BLAKE2B_HASH_BYTES,
                         sig_block + (1 + ED_PUBLIC_KEY_BYTES)) != 0) {
      printf("[%s:%d] signing signature failed\n", __func__, __LINE__);
      return -1;
    }

    // create a signature unlock block
    if (unlock_blocks_add_signature(unlock_blocks, sig_block, ED25519_SIGNATURE_BLOCK_BYTES) != 0) {
      printf("[%s:%d] add signature block failed\n", __func__, __LINE__);
      return -1;
    }

    // if input has NFT or Alias address save its address in unlock block index list
    /*if (input->address) {
      if (update_unlock_block_index(input, *unlock_blocks, unlock_block_index_list) != 0) {
        printf("[%s:%d] can not update unlock block index list\n", __func__, __LINE__);
        return -1;
      }
    }*/
  } else {
    // public key is found in the unlocked block, just add a reference
    if (unlock_blocks_add_reference(unlock_blocks, (uint16_t)pub_index) != 0) {
      printf("[%s:%d] add reference block failed\n", __func__, __LINE__);
      return -1;
    }
  }

  return 0;
}

static int create_unlock_block_alias_or_nft(address_t* address, unlock_block_index_list_t* unlock_block_index_list,
                                            unlock_list_t** unlock_blocks) {
  if (address == NULL || unlock_block_index_list == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  unlock_block_index_list_t* elm;
  LL_FOREACH(unlock_block_index_list, elm) {
    unlock_block_index_t* unlock_block_index = elm->unlock_block_index;
    if (memcmp(&unlock_block_index->address, address, sizeof(unlock_block_index->address)) == 0) {
      switch (elm->unlock_block_index->address.type) {
        case ADDRESS_TYPE_ALIAS:
          if (unlock_blocks_add_alias(unlock_blocks, unlock_block_index->index) != 0) {
            printf("[%s:%d] adding Alias unlock block failed\n", __func__, __LINE__);
            return -1;
          }
          return 0;
        case ADDRESS_TYPE_NFT:
          if (unlock_blocks_add_nft(unlock_blocks, unlock_block_index->index) != 0) {
            printf("[%s:%d] adding NFT unlock block failed\n", __func__, __LINE__);
            return -1;
          }
          return 0;
        default:
          printf("[%s:%d] address must be Alias or NFT.\n", __func__, __LINE__);
          return -1;
      }
    }
  }

  printf("[%s:%d] Alias or NFT address was not found in unlock block index list.\n", __func__, __LINE__);
  return -1;
}

int signing_transaction_sign(utxo_inputs_list_t* inputs, byte_t essence_hash[], unlock_list_t** unlock_blocks) {
  if (inputs == NULL || essence_hash == NULL || *unlock_blocks != NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  unlock_block_index_list_t* unlock_block_index_list = NULL;

  utxo_inputs_list_t* elm;
  LL_FOREACH(inputs, elm) {
    if (elm->input->keypair) {
      if (create_unlock_block_ed25519(elm->input, essence_hash, &unlock_block_index_list, unlock_blocks) != 0) {
        printf("[%s:%d] creating unlock block for ed25519 address failed.\n", __func__, __LINE__);
        unlock_block_index_list_free(unlock_block_index_list);
        return -1;
      }
    } /*else if (elm->input->address) {
      if (create_unlock_block_alias_or_nft(elm->input->address, unlock_block_index_list, unlock_blocks) != 0) {
        printf("[%s:%d] creating unlock block for Alias or NFT address failed.\n", __func__, __LINE__);
        unlock_block_index_list_free(unlock_block_index_list);
        return -1;
      }
    }*/
    else {
      printf("[%s:%d] input must have ed25519 keypair, Alias address or NFT address.\n", __func__, __LINE__);
      unlock_block_index_list_free(unlock_block_index_list);
      return -1;
    }
  }

  // Clean up
  unlock_block_index_list_free(unlock_block_index_list);

  return 0;
}
