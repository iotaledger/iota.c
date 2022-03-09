// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/address.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/outputs.h"

// maximum number of unlock condition blocks
#define MAX_NFT_CONDITION_BLOCKS_COUNT 4
// maximum number of feature blocks
#define MAX_NFT_FEATURE_BLOCKS_COUNT 3
// maximum number of immutable feature blocks
#define MAX_NFT_IMMUTABLE_FEATURE_BLOCKS_COUNT 2

output_nft_t* output_nft_new(uint64_t amount, native_tokens_list_t* tokens, byte_t nft_id[],
                             cond_blk_list_t* cond_blocks, feat_blk_list_t* feat_blocks,
                             feat_blk_list_t* immut_feat_blocks) {
  if (nft_id == NULL || cond_blocks == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  // validate unlock condition parameter
  if (cond_blk_list_len(cond_blocks) > MAX_NFT_CONDITION_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d condition blocks\n", __func__, __LINE__, MAX_NFT_CONDITION_BLOCKS_COUNT);
    return NULL;
  } else {
    // must not contain UNLOCK_COND_STATE or UNLOCK_COND_GOVERNOR
    if (cond_blk_list_get_type(cond_blocks, UNLOCK_COND_STATE) ||
        cond_blk_list_get_type(cond_blocks, UNLOCK_COND_GOVERNOR)) {
      printf("[%s:%d] State Controller/Governor conditions are not allowed\n", __func__, __LINE__);
      return NULL;
    }
    // Address Unlock Condition must be present.
    if (!cond_blk_list_get_type(cond_blocks, UNLOCK_COND_ADDRESS)) {
      printf("[%s:%d] Address Unlock Condition must be present\n", __func__, __LINE__);
      return NULL;
    }
  }

  // validate feature block parameter
  if (feat_blk_list_len(feat_blocks) > MAX_NFT_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d feature blocks\n", __func__, __LINE__, MAX_NFT_FEATURE_BLOCKS_COUNT);
    return NULL;
  }

  // validate immutable feature block parameter
  if (feat_blk_list_len(immut_feat_blocks) > MAX_NFT_IMMUTABLE_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d immutable feature blocks\n", __func__, __LINE__,
           MAX_NFT_IMMUTABLE_FEATURE_BLOCKS_COUNT);
    return NULL;
  }

  // FIXME : Validation - Address field of the Address Unlock Condition must not be the same as the NFT address derived
  // from NFT ID

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
      int res = native_tokens_add(&output->native_tokens, elm->token->token_id, elm->token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to NFT output\n", __func__, __LINE__);
        output_nft_free(output);
        return NULL;
      }
    }
  }

  // add nft id
  memcpy(output->nft_id, nft_id, ADDRESS_NFT_BYTES);

  // add condition blocks
  output->unlock_conditions = cond_blk_list_clone(cond_blocks);
  if (!output->unlock_conditions) {
    printf("[%s:%d] can not add unlock conditions to NFT output\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }

  // add feature blocks
  output->feature_blocks = feat_blk_list_clone(feat_blocks);

  // add immutable feature blocks
  output->immutable_blocks = feat_blk_list_clone(immut_feat_blocks);

  return output;
}

void output_nft_free(output_nft_t* output) {
  if (output) {
    if (output->native_tokens) {
      native_tokens_free(output->native_tokens);
    }
    cond_blk_list_free(output->unlock_conditions);
    feat_blk_list_free(output->feature_blocks);
    feat_blk_list_free(output->immutable_blocks);
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
  length += ADDRESS_NFT_BYTES;
  // unlock conditions
  length += cond_blk_list_serialize_len(output->unlock_conditions);
  // feature blocks
  length += feat_blk_list_serialize_len(output->feature_blocks);
  // immutable feature blocks
  length += feat_blk_list_serialize_len(output->immutable_blocks);

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
  memcpy(buf + offset, output->nft_id, ADDRESS_NFT_BYTES);
  offset += ADDRESS_NFT_BYTES;

  // unlock conditions
  offset += cond_blk_list_serialize(&output->unlock_conditions, buf + offset, buf_len - offset);

  // feature blocks
  if (output->feature_blocks) {
    offset += feat_blk_list_serialize(&output->feature_blocks, buf + offset, buf_len - offset);
  } else {
    memset(buf + offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  // immutable feature blocks
  if (output->immutable_blocks) {
    offset += feat_blk_list_serialize(&output->immutable_blocks, buf + offset, buf_len - offset);
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
  if (buf_len < offset + ADDRESS_NFT_BYTES) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  }
  memcpy(&output->nft_id, &buf[offset], ADDRESS_NFT_BYTES);
  offset += ADDRESS_NFT_BYTES;

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

  // feature blocks
  uint8_t feat_block_count = 0;
  memcpy(&feat_block_count, &buf[offset], sizeof(uint8_t));
  if (feat_block_count > MAX_NFT_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] invalid feature block count\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  } else if (feat_block_count > 0) {
    output->feature_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->feature_blocks) {
      printf("[%s:%d] can not deserialize feature blocks\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += feat_blk_list_serialize_len(output->feature_blocks);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
  }

  // immutable feature blocks
  uint8_t immut_feat_block_count = 0;
  memcpy(&immut_feat_block_count, &buf[offset], sizeof(uint8_t));
  if (immut_feat_block_count > MAX_NFT_IMMUTABLE_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] invalid immutable feature block count\n", __func__, __LINE__);
    output_nft_free(output);
    return NULL;
  } else if (immut_feat_block_count > 0) {
    output->immutable_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->immutable_blocks) {
      printf("[%s:%d] can not deserialize immutable feature blocks\n", __func__, __LINE__);
      output_nft_free(output);
      return NULL;
    }
    offset += feat_blk_list_serialize_len(output->immutable_blocks);
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
    memcpy(new_output->nft_id, output->nft_id, ADDRESS_NFT_BYTES);
    new_output->unlock_conditions = cond_blk_list_clone(output->unlock_conditions);
    new_output->feature_blocks = feat_blk_list_clone(output->feature_blocks);
    new_output->immutable_blocks = feat_blk_list_clone(output->immutable_blocks);
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
  dump_hex_str(output->nft_id, ADDRESS_NFT_BYTES);

  // print unlock condition blocks
  cond_blk_list_print(output->unlock_conditions, indentation + 1);
  // print feature blocks
  feat_blk_list_print(output->feature_blocks, false, indentation + 1);
  // print immutable feature blocks
  feat_blk_list_print(output->immutable_blocks, true, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
