// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/address.h"
#include "core/models/outputs/output_basic.h"
#include "core/models/outputs/outputs.h"
#include "core/types.h"

// maximum number of unlock condition blocks
#define MAX_BASIC_CONDITION_BLOCKS_COUNT 4
// maximum number of feature blocks
#define MAX_BASIC_FEATURE_BLOCKS_COUNT 3

output_basic_t* output_basic_new(uint64_t amount, native_tokens_list_t* tokens, cond_blk_list_t* cond_blocks,
                                 feat_blk_list_t* feat_blocks) {
  if (cond_blocks == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  // validate unlock condition parameter
  // It must hold true that 1 ≤ Unlock Conditions Count ≤ 4
  if (cond_blk_list_len(cond_blocks) == 0 || cond_blk_list_len(cond_blocks) > MAX_BASIC_CONDITION_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d condition blocks amd atleast 1\n", __func__, __LINE__,
           MAX_BASIC_CONDITION_BLOCKS_COUNT);
    return NULL;
  } else {
    // must no contain UNLOCK_COND_STATE or UNLOCK_COND_GOVERNOR
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
  if (feat_blk_list_len(feat_blocks) > MAX_BASIC_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d feature blocks\n", __func__, __LINE__, MAX_BASIC_FEATURE_BLOCKS_COUNT);
    return NULL;
  } else {
    // must no contain FEAT_ISSUER_BLOCK
    if (feat_blk_list_get_type(feat_blocks, FEAT_ISSUER_BLOCK)) {
      printf("[%s:%d] Issuer feature block is not allowed\n", __func__, __LINE__);
      return NULL;
    }
  }

  // create a basic output object
  output_basic_t* output = malloc(sizeof(output_basic_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  // init the basic object
  memset(output, 0, sizeof(output_basic_t));

  // add amount
  output->amount = amount;

  // add native token
  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_list_t* elm;
    LL_FOREACH(tokens, elm) {
      int res = native_tokens_add(&output->native_tokens, elm->token->token_id, &elm->token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to basic output\n", __func__, __LINE__);
        output_basic_free(output);
        return NULL;
      }
    }
  }

  // add condition blocks
  output->unlock_conditions = cond_blk_list_clone(cond_blocks);
  if (!output->unlock_conditions) {
    printf("[%s:%d] can not add unlock conditions to Basic output\n", __func__, __LINE__);
    output_basic_free(output);
    return NULL;
  }

  // add feature blocks
  output->feature_blocks = feat_blk_list_clone(feat_blocks);

  return output;
}

void output_basic_free(output_basic_t* output) {
  if (output) {
    if (output->native_tokens) {
      native_tokens_free(output->native_tokens);
    }
    cond_blk_list_free(output->unlock_conditions);
    feat_blk_list_free(output->feature_blocks);
    free(output);
  }
}

size_t output_basic_serialize_len(output_basic_t* output) {
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
  // unlock conditions
  length += cond_blk_list_serialize_len(output->unlock_conditions);
  // feature blocks
  length += feat_blk_list_serialize_len(output->feature_blocks);

  return length;
}

size_t output_basic_serialize(output_basic_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = output_basic_serialize_len(output);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;

  // fill-in Basic Output type
  memset(buf, OUTPUT_BASIC, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // amount
  memcpy(buf + offset, &output->amount, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  offset += native_tokens_serialize(&output->native_tokens, buf + offset, buf_len - offset);

  // unlock conditions
  offset += cond_blk_list_serialize(&output->unlock_conditions, buf + offset, buf_len - offset);

  // feature blocks
  if (output->feature_blocks) {
    offset += feat_blk_list_serialize(&output->feature_blocks, buf + offset, buf_len - offset);
  } else {
    memset(buf + offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  return offset;
}

output_basic_t* output_basic_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_basic_t* output = malloc(sizeof(output_basic_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  memset(output, 0, sizeof(output_basic_t));

  size_t offset = 0;
  // output type
  if (buf[offset] != OUTPUT_BASIC) {
    printf("[%s:%d] buffer does not contain Basic Output object\n", __func__, __LINE__);
    output_basic_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_basic_free(output);
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
      output_basic_free(output);
      return NULL;
    }
  }
  offset += native_tokens_serialize_len(output->native_tokens);

  // unlock condition blocks
  uint8_t unlock_count = 0;
  memcpy(&unlock_count, &buf[offset], sizeof(uint8_t));
  if (unlock_count == 0 || unlock_count > MAX_BASIC_CONDITION_BLOCKS_COUNT) {
    printf("[%s:%d] invalid unlock block count\n", __func__, __LINE__);
    output_basic_free(output);
    return NULL;
  } else {
    output->unlock_conditions = cond_blk_list_deserialize(buf + offset, buf_len - offset);
    if (!output->unlock_conditions) {
      printf("[%s:%d] can not deserialize unlock conditions\n", __func__, __LINE__);
      output_basic_free(output);
      return NULL;
    }
    offset += cond_blk_list_serialize_len(output->unlock_conditions);
  }

  // feature blocks
  uint8_t feat_block_count = 0;
  memcpy(&feat_block_count, &buf[offset], sizeof(uint8_t));
  if (feat_block_count > MAX_BASIC_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] invalid feature block count\n", __func__, __LINE__);
    output_basic_free(output);
    return NULL;
  } else if (feat_block_count > 0) {
    output->feature_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->feature_blocks) {
      printf("[%s:%d] can not deserialize feature blocks\n", __func__, __LINE__);
      output_basic_free(output);
      return NULL;
    }
    offset += feat_blk_list_serialize_len(output->feature_blocks);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_basic_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
  }

  return output;
}

output_basic_t* output_basic_clone(output_basic_t const* const output) {
  if (output == NULL) {
    return NULL;
  }

  output_basic_t* new_output = malloc(sizeof(output_basic_t));
  if (new_output) {
    new_output->amount = output->amount;
    new_output->native_tokens = native_tokens_clone(output->native_tokens);
    new_output->unlock_conditions = cond_blk_list_clone(output->unlock_conditions);
    new_output->feature_blocks = feat_blk_list_clone(output->feature_blocks);
  }

  return new_output;
}

void output_basic_print(output_basic_t* output, uint8_t indentation) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("%sBasic Output: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tAmount: %" PRIu64 "\n", PRINT_INDENTATION(indentation), output->amount);

  // print native tokens
  native_tokens_print(output->native_tokens, indentation + 1);
  // print unlock condition blocks
  cond_blk_list_print(output->unlock_conditions, indentation + 1);
  // print feature blocks
  feat_blk_list_print(output->feature_blocks, false, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
