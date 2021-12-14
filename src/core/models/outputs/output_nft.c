// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/output_nft.h"
#include "core/address.h"
#include "uthash.h"

output_nft_t* output_nft_new(void* address, uint64_t amount, native_tokens_t** tokens, void* nft_id, byte_t* metadata,
                             uint32_t metadata_len, void* feature_blocks) {
  if (address == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (amount < 1000000) {
    printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
    return NULL;
  }

  output_nft_t* output = malloc(sizeof(output_nft_t));
  if (!output) {
    return NULL;
  }

  switch (((address_t*)address)->type) {
    case ADDRESS_TYPE_ED25519:
      output->address = malloc(ADDRESS_ED25519_BYTES);
      if (!output->address) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }
      memcpy(output->address, ((address_t*)address)->address, ADDRESS_ED25519_BYTES);
      break;
    case ADDRESS_TYPE_ALIAS:
      output->address = malloc(ADDRESS_ALIAS_BYTES);
      if (!output->address) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }
      memcpy(output->address, ((address_t*)address)->address, ADDRESS_ALIAS_BYTES);
      break;
    case ADDRESS_TYPE_NFT:
      output->address = malloc(ADDRESS_NFT_BYTES);
      if (!output->address) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }
      memcpy(output->address, ((address_t*)address)->address, ADDRESS_NFT_BYTES);
      break;
    default:
      printf("[%s:%d] unknown address type\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
  }

  output->amount = amount;

  if (tokens != NULL) {
    // output->native_tokens = native_tokens_new();

    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, *tokens, token, token_tmp) {
      /*int res = native_tokens_add(&output->native_tokens, token->token_id, uint256_to_string(token->amount));
      if (res == -1) {
        printf("[%s:%d] can not add native token to NFT output\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }*/
    }
  }

  output->nft_id = malloc(20);
  if (!output->nft_id) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  memcpy(output->nft_id, nft_id, 20);

  if (metadata_len > 0) {
    output->immutable_metadata = malloc(metadata_len);
    if (!output->immutable_metadata) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    memcpy(output->immutable_metadata, metadata, metadata_len);
  }

  return output;
}

void output_nft_free(output_nft_t* output) {
  if (output) {
    if (output->address) {
      free(output->address);
    }
    if (output->native_tokens) {
      // native_tokens_free(&output->native_tokens);
    }
    if (output->nft_id) {
      free(output->nft_id);
    }
    if (output->immutable_metadata) {
      free(output->immutable_metadata);
    }
    if (output->feature_blocks) {
      // feature_blocks_free(&output->feature_blocks);
    }
    free(output);
  }
}
