// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/address.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"

#define MIN_NFT_CONDITION_BLOCKS_COUNT 1
// maximum number of unlock condition blocks
#define MAX_NFT_CONDITION_BLOCKS_COUNT 4
// maximum number of features
#define MAX_NFT_FEATURES_COUNT 3
// maximum number of immutable features
#define MAX_NFT_IMMUTABLE_FEATURES_COUNT 2

output_nft_t* output_nft_new(uint64_t amount, native_tokens_list_t* tokens, byte_t nft_id[],
                             cond_blk_list_t* cond_blocks, feature_list_t* features, feature_list_t* immut_features) {
  if (nft_id == NULL || cond_blocks == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_nft_t* output = malloc(sizeof(output_nft_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  // init the nft object
  memset(output, 0, sizeof(output_nft_t));

  // add amount
  output->amount = amount;

  // add native tokens
  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_list_t* elm;
    LL_FOREACH(tokens, elm) {
      int res = native_tokens_add(&output->native_tokens, elm->token->token_id, &elm->token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to NFT output\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }
    }
  }

  // add nft id
  memcpy(output->nft_id, nft_id, NFT_ID_BYTES);

  // add condition blocks
  output->unlock_conditions = cond_blk_list_clone(cond_blocks);
  if (!output->unlock_conditions) {
    printf("[%s:%d] can not add unlock conditions to NFT output\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }

  // add features
  output->features = feature_list_clone(features);

  // add immutable features
  output->immutable_features = feature_list_clone(immut_features);

  return output;
}

void output_nft_free(output_nft_t* output) {
  if (output) {
    if (output->native_tokens) {
      native_tokens_free(output->native_tokens);
    }
    cond_blk_list_free(output->unlock_conditions);
    feature_list_free(output->features);
    feature_list_free(output->immutable_features);
    free(output);
  }
}

size_t output_nft_serialize_len(output_nft_t* output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t length = 0;

  // output type
  length += sizeof(uint8_t);
  // amount
  length += sizeof(uint64_t);
  // native tokens
  length += native_tokens_serialize_len(output->native_tokens);
  // NFT ID
  length += NFT_ID_BYTES;
  // unlock conditions
  length += cond_blk_list_serialize_len(output->unlock_conditions);
  // features
  length += feature_list_serialize_len(output->features);
  // immutable features
  length += feature_list_serialize_len(output->immutable_features);

  return length;
}

size_t output_nft_serialize(output_nft_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = output_nft_serialize_len(output);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;

  // fill-in NFT Output type
  memset(buf, OUTPUT_NFT, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // amount
  memcpy(buf + offset, &output->amount, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  offset += native_tokens_serialize(&output->native_tokens, buf + offset, buf_len - offset);

  // NFT ID
  memcpy(buf + offset, output->nft_id, NFT_ID_BYTES);
  offset += NFT_ID_BYTES;

  // unlock conditions
  offset += cond_blk_list_serialize(&output->unlock_conditions, buf + offset, buf_len - offset);

  // features
  if (output->features) {
    offset += feature_list_serialize(&output->features, buf + offset, buf_len - offset);
  } else {
    memset(buf + offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  // immutable featurs
  if (output->immutable_features) {
    offset += feature_list_serialize(&output->immutable_features, buf + offset, buf_len - offset);
  } else {
    memset(buf + offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  return offset;
}

output_nft_t* output_nft_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_nft_t* output = malloc(sizeof(output_nft_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  memset(output, 0, sizeof(output_nft_t));

  size_t offset = 0;

  // output type
  if (buf[offset] != OUTPUT_NFT) {
    printf("[%s:%d] buffer does not contain NFT Output object\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  memcpy(&output->amount, &buf[offset], sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  uint8_t tokens_count = 0;
  memcpy(&tokens_count, &buf[offset], sizeof(uint8_t));
  if (tokens_count > 0) {
    output->native_tokens = native_tokens_deserialize(&buf[offset], buf_len - offset);
    if (!output->native_tokens) {
      printf("[%s:%d] can not deserialize native tokens\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
  }
  offset += native_tokens_serialize_len(output->native_tokens);

  // NFT ID
  if (buf_len < offset + NFT_ID_BYTES) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  memcpy(&output->nft_id, &buf[offset], NFT_ID_BYTES);
  offset += NFT_ID_BYTES;

  // unlock condition blocks
  uint8_t unlock_count = 0;
  memcpy(&unlock_count, &buf[offset], sizeof(uint8_t));
  if (unlock_count > MAX_NFT_CONDITION_BLOCKS_COUNT) {
    printf("[%s:%d] invalid unlock block count\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  } else {
    output->unlock_conditions = cond_blk_list_deserialize(buf + offset, buf_len - offset);
    if (!output->unlock_conditions) {
      printf("[%s:%d] can not deserialize unlock conditions\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += cond_blk_list_serialize_len(output->unlock_conditions);
  }

  // features
  uint8_t feat_count = 0;
  memcpy(&feat_count, &buf[offset], sizeof(uint8_t));
  if (feat_count > MAX_NFT_FEATURES_COUNT) {
    printf("[%s:%d] invalid feature count\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  } else if (feat_count > 0) {
    output->features = feature_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->features) {
      printf("[%s:%d] can not deserialize features\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += feature_list_serialize_len(output->features);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
  }

  // immutable features
  uint8_t immut_feat_count = 0;
  memcpy(&immut_feat_count, &buf[offset], sizeof(uint8_t));
  if (immut_feat_count > MAX_NFT_IMMUTABLE_FEATURES_COUNT) {
    printf("[%s:%d] invalid immutable feature count\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  } else if (immut_feat_count > 0) {
    output->immutable_features = feature_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->immutable_features) {
      printf("[%s:%d] can not deserialize immutable features\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += feature_list_serialize_len(output->immutable_features);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
  }

  return output;
}

output_nft_t* output_nft_clone(output_nft_t const* const output) {
  if (output == NULL) {
    return NULL;
  }

  output_nft_t* new_output = malloc(sizeof(output_nft_t));
  if (new_output) {
    new_output->amount = output->amount;
    new_output->native_tokens = native_tokens_clone(output->native_tokens);
    memcpy(new_output->nft_id, output->nft_id, NFT_ID_BYTES);
    new_output->unlock_conditions = cond_blk_list_clone(output->unlock_conditions);
    new_output->features = feature_list_clone(output->features);
    new_output->immutable_features = feature_list_clone(output->immutable_features);
  }

  return new_output;
}

void output_nft_print(output_nft_t* output, uint8_t indentation) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("%sNFT Output: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tAmount: %" PRIu64 "\n", PRINT_INDENTATION(indentation), output->amount);

  // print native tokens
  native_tokens_print(output->native_tokens, indentation + 1);

  // print NFT ID
  printf("%s\tNFT ID: ", PRINT_INDENTATION(indentation));
  dump_hex_str(output->nft_id, NFT_ID_BYTES);

  // print unlock condition blocks
  cond_blk_list_print(output->unlock_conditions, indentation + 1);
  // print features
  feature_list_print(output->features, false, indentation + 1);
  // print immutable features
  feature_list_print(output->immutable_features, true, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}

bool output_nft_syntactic(output_nft_t* output) {
  // amount must <= Max IOTA Supply
  if (output->amount > MAX_IOTA_SUPPLY) {
    printf("[%s:%d] amount bigger than MAX_IOTA_SUPPLY\n", __func__, __LINE__);
    return false;
  }

  // Native token count must not greater than Max Native Tokens Count
  // Native token must be lexicographically sorted based on Token ID
  // Each Native Token must be unique in the set of Native Tokens based on its Token ID, no duplicates are allowed
  // Amount of native token must not be zero
  if (!native_tokens_syntactic(&output->native_tokens)) {
    return false;
  }

  // == Unlock condition validation ===
  // 1 <= unlock conditions count <= 4
  if ((cond_blk_list_len(output->unlock_conditions) < MIN_NFT_CONDITION_BLOCKS_COUNT) ||
      (cond_blk_list_len(output->unlock_conditions) > MAX_NFT_CONDITION_BLOCKS_COUNT)) {
    printf("[%s:%d] Unlock condition count must be %d\n", __func__, __LINE__, MAX_NFT_CONDITION_BLOCKS_COUNT);
    return false;
  }
  // Unlock Condition types:
  // - Address Unlock (mandatory)
  // - Storage Deposit Unlock
  // - Timelock Unlock
  // - Expiration Unlock
  unlock_cond_blk_t* addr_unlock = cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_ADDRESS);
  if (addr_unlock == NULL) {
    printf("[%s:%d] Address Unlock must be present\n", __func__, __LINE__);
    return false;
  }
  if (cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE) ||
      cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_GOVERNOR) ||
      cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_IMMUT_ALIAS)) {
    printf("[%s:%d] invalid unlock condition\n", __func__, __LINE__);
    return false;
  }
  // Unlock Condition must be sorted in ascending order based on their type
  cond_blk_list_sort(&output->unlock_conditions);

  // == Feature Blocks validation ===
  // 0<= feature count <= 3
  if (feature_list_len(output->features) > MAX_NFT_FEATURES_COUNT) {
    printf("[%s:%d] invalid feature count must smaller than %d\n", __func__, __LINE__, MAX_NFT_FEATURES_COUNT);
    return false;
  }
  if (feature_list_len(output->features) > 0) {
    // feature types
    // - Sender
    // - Metadata
    // - Tag
    if (feature_list_get_type(output->features, FEAT_ISSUER_TYPE)) {
      printf("[%s:%d] Issuer feature is not allowed\n", __func__, __LINE__);
      return false;
    }
  }
  // Blocks must stored in ascending order based on their Block Type
  feature_list_sort(&output->features);

  // == Immutable Feature Blocks validation ===
  // 0<= immutable feature count <= 2
  if (feature_list_len(output->immutable_features) > MAX_NFT_IMMUTABLE_FEATURES_COUNT) {
    printf("[%s:%d] immutable feature count must smaller than %d\n", __func__, __LINE__,
           MAX_NFT_IMMUTABLE_FEATURES_COUNT);
    return false;
  }

  if (feature_list_len(output->immutable_features) > 0) {
    // immutable feature types
    // - Issuer
    // - Metadata
    if (feature_list_get_type(output->immutable_features, FEAT_SENDER_TYPE) ||
        feature_list_get_type(output->immutable_features, FEAT_TAG_TYPE)) {
      printf("[%s:%d] Sender and Tag Feature are not allowed\n", __func__, __LINE__);
      return false;
    }
  }

  // Blocks must stored in ascending order based on their Block Type
  feature_list_sort(&output->immutable_features);

  // Address field of the Address Unlock Condition must not be the same as the NFT address derived from NFT ID
  if (((address_t*)addr_unlock->block)->type != ADDRESS_TYPE_ED25519) {
    if (memcmp(((address_t*)addr_unlock->block)->address, output->nft_id, NFT_ID_BYTES) == 0) {
      printf("[%s:%d] Address field must not be the same as the NFT address derived from NFT ID\n", __func__, __LINE__);
      return false;
    }
  }

  return true;
}
