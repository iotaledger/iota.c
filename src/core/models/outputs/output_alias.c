// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/address.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/outputs.h"
#include "uthash.h"
#include "utlist.h"

// minumum dust allowance
#define MIN_DUST_ALLOWANCE 1000000

// maximum number of feature blocks
#define MAX_FEATURE_BLOCKS_COUNT 3

output_alias_t* output_alias_new(uint64_t amount, native_tokens_t* tokens, byte_t alias_id[], address_t* st_ctl,
                                 address_t* gov_ctl, uint32_t state_index, byte_t* metadata, uint32_t metadata_len,
                                 uint32_t foundry_counter, feat_blk_list_t* feat_blocks) {
  if (alias_id == NULL || st_ctl == NULL || gov_ctl == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (amount < MIN_DUST_ALLOWANCE) {
    printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
    return NULL;
  }

  if (buf_all_zeros(alias_id, ADDRESS_ALIAS_BYTES)) {
    if (state_index != 0 || foundry_counter != 0) {
      printf("[%s:%d] when alias ID is zero then state index and foundry counter must be zero\n", __func__, __LINE__);
      return NULL;
    }
  }

  if (st_ctl->type == ADDRESS_TYPE_ALIAS && memcmp(st_ctl->address, alias_id, ADDRESS_ALIAS_BYTES) == 0) {
    printf("[%s:%d] state controller address must be different than alias ID\n", __func__, __LINE__);
    return NULL;
  }

  if (gov_ctl->type == ADDRESS_TYPE_ALIAS && memcmp(gov_ctl->address, alias_id, ADDRESS_ALIAS_BYTES) == 0) {
    printf("[%s:%d] governance controller address must be different than alias ID\n", __func__, __LINE__);
    return NULL;
  }

  if (feat_blk_list_len(feat_blocks) > MAX_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d feature blocks\n", __func__, __LINE__, MAX_FEATURE_BLOCKS_COUNT);
    return NULL;
  }

  output_alias_t* output = malloc(sizeof(output_alias_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->native_tokens = NULL;
  output->st_ctl = NULL;
  output->gov_ctl = NULL;
  output->state_metadata = NULL;
  output->feature_blocks = NULL;

  // amount
  output->amount = amount;

  // native tokens
  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, tokens, token, token_tmp) {
      int res = native_tokens_add(&output->native_tokens, token->token_id, token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to Alias output\n", __func__, __LINE__);
        output_alias_free(output);
        return NULL;
      }
    }
  }

  // alias ID
  memcpy(output->alias_id, alias_id, ADDRESS_ALIAS_BYTES);

  // state controller
  output->st_ctl = address_clone(st_ctl);
  if (!output->st_ctl) {
    printf("[%s:%d] can not add State Controller to Alias output\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }

  // governance controller
  output->gov_ctl = address_clone(gov_ctl);
  if (!output->gov_ctl) {
    printf("[%s:%d] can not add Governance Controller to Alias output\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }

  // state index
  output->state_index = state_index;

  // metadata
  if (metadata_len > 0 && metadata != NULL) {
    output->state_metadata = byte_buf_new_with_data(metadata, metadata_len);
    if (!output->state_metadata) {
      printf("[%s:%d] can not add metadata to Alias output\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
  }

  // foundry counter
  output->foundry_counter = foundry_counter;

  // feature blocks
  if (feat_blocks != NULL) {
    output->feature_blocks = new_feat_blk_list();
    feat_blk_list_t* feat;
    int res;
    LL_FOREACH(feat_blocks, feat) {
      switch (feat->blk->type) {
        case FEAT_SENDER_BLOCK:
          res = feat_blk_list_add_sender(&output->feature_blocks, feat->blk->block);
          break;
        case FEAT_ISSUER_BLOCK:
          res = feat_blk_list_add_issuer(&output->feature_blocks, feat->blk->block);
          break;
        case FEAT_METADATA_BLOCK: {
          feat_metadata_blk_t* block_metadata = (feat_metadata_blk_t*)feat->blk->block;
          res = feat_blk_list_add_metadata(&output->feature_blocks, block_metadata->data, block_metadata->data_len);
          break;
        }
        default:
          printf("[%s:%d] unsupported feature block type, can not add it to Alias output\n", __func__, __LINE__);
          output_alias_free(output);
          return NULL;
      }
      if (res == -1) {
        printf("[%s:%d] can not add feature block to Alias output\n", __func__, __LINE__);
        output_alias_free(output);
        return NULL;
      }
    }
  }

  return output;
}

void output_alias_free(output_alias_t* output) {
  if (output) {
    if (output->native_tokens) {
      native_tokens_free(&output->native_tokens);
    }
    if (output->st_ctl) {
      free_address(output->st_ctl);
    }
    if (output->gov_ctl) {
      free_address(output->gov_ctl);
    }
    if (output->state_metadata) {
      byte_buf_free(output->state_metadata);
    }
    if (output->feature_blocks) {
      free_feat_blk_list(output->feature_blocks);
    }
    free(output);
  }
}

size_t output_alias_serialize_len(output_alias_t* output) {
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
  length += native_tokens_serialize_len(&output->native_tokens);
  // alias ID
  length += ADDRESS_ALIAS_BYTES;
  // state controller
  length += address_serialized_len(output->st_ctl);
  // governance controller
  length += address_serialized_len(output->gov_ctl);
  // state index
  length += sizeof(uint32_t);
  // metadata length
  length += sizeof(uint32_t);
  // metadata
  if (output->state_metadata) {
    length += output->state_metadata->len;
  }
  // foundry counter
  length += sizeof(uint32_t);
  // feature blocks
  length += feat_blk_list_serialize_len(output->feature_blocks);

  return length;
}

size_t output_alias_serialize(output_alias_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = output_alias_serialize_len(output);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  byte_t* offset = buf;

  // fill-in Alias Output type
  memset(offset, OUTPUT_ALIAS, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // amount
  memcpy(offset, &output->amount, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  if (output->native_tokens) {
    offset +=
        native_tokens_serialize(&output->native_tokens, offset, native_tokens_serialize_len(&output->native_tokens));
  } else {
    memset(offset, 0, sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  // alias ID
  memcpy(offset, output->alias_id, ADDRESS_ALIAS_BYTES);
  offset += ADDRESS_ALIAS_BYTES;

  // state controller
  offset += address_serialize(output->st_ctl, offset, address_serialized_len(output->st_ctl));

  // governance controller
  offset += address_serialize(output->gov_ctl, offset, address_serialized_len(output->gov_ctl));

  // state index
  memcpy(offset, &output->state_index, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // immutable metadata
  if (output->state_metadata) {
    uint32_t metadata_len = output->state_metadata->len;
    memcpy(offset, &metadata_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(offset, output->state_metadata->data, metadata_len);
    offset += metadata_len;
  } else {
    memset(offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
  }

  // foundry counter
  memcpy(offset, &output->foundry_counter, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // feature blocks
  if (output->feature_blocks) {
    offset +=
        feat_blk_list_serialize(output->feature_blocks, offset, feat_blk_list_serialize_len(output->feature_blocks));
  } else {
    memset(offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  return expected_bytes;
}

output_alias_t* output_alias_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  output_alias_t* output = malloc(sizeof(output_alias_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->native_tokens = NULL;
  output->st_ctl = NULL;
  output->gov_ctl = NULL;
  output->state_metadata = NULL;
  output->feature_blocks = NULL;

  size_t offset = 0;

  // output type
  if (buf[offset] != OUTPUT_ALIAS) {
    printf("[%s:%d] buffer does not contain Alias Output object\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  memcpy(&output->amount, &buf[offset], sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  uint16_t tokens_count = 0;
  memcpy(&tokens_count, &buf[offset], sizeof(uint16_t));
  if (tokens_count > 0) {
    output->native_tokens = native_tokens_deserialize(&buf[offset], buf_len - offset);
    if (!output->native_tokens) {
      printf("[%s:%d] can not deserialize native tokens\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    offset += native_tokens_serialize_len(&output->native_tokens);
  } else {
    offset += sizeof(uint16_t);
  }

  // alias ID
  if (buf_len < offset + ADDRESS_ALIAS_BYTES) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  memcpy(&output->alias_id, &buf[offset], ADDRESS_ALIAS_BYTES);
  offset += ADDRESS_ALIAS_BYTES;

  // state controller
  output->st_ctl = address_deserialize(&buf[offset], buf_len - offset);
  if (!output->st_ctl) {
    printf("[%s:%d] can not deserialize state controller\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  offset += address_serialized_len(output->st_ctl);

  // governance controller
  output->gov_ctl = address_deserialize(&buf[offset], buf_len - offset);
  if (!output->gov_ctl) {
    printf("[%s:%d] can not deserialize governance controller\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  offset += address_serialized_len(output->gov_ctl);

  // state index
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  memcpy(&output->state_index, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // metadata length
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  uint32_t metadata_len;
  memcpy(&metadata_len, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // metadata
  if (metadata_len > 0) {
    if (buf_len < offset + metadata_len) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    output->state_metadata = byte_buf_new_with_data(&buf[offset], metadata_len);
    if (!output->state_metadata) {
      printf("[%s:%d] can not deserialize metadata\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    offset += metadata_len;
  }

  // foundry counter
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  memcpy(&output->foundry_counter, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // feature blocks
  uint8_t feat_block_count = *((uint8_t*)&buf[offset]);
  if (feat_block_count > 0) {
    output->feature_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->feature_blocks) {
      printf("[%s:%d] can not deserialize feature blocks\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
  }

  return output;
}

output_alias_t* output_alias_clone(output_alias_t const* const output) {
  if (output == NULL) {
    return NULL;
  }

  output_alias_t* new_output = malloc(sizeof(output_alias_t));
  if (new_output) {
    new_output->amount = output->amount;
    new_output->native_tokens = native_tokens_clone(output->native_tokens);
    memcpy(new_output->alias_id, output->alias_id, ADDRESS_ALIAS_BYTES);
    new_output->st_ctl = address_clone(output->st_ctl);
    new_output->gov_ctl = address_clone(output->gov_ctl);
    new_output->state_index = output->state_index;
    new_output->state_metadata = byte_buf_clone(output->state_metadata);
    new_output->foundry_counter = output->foundry_counter;
    new_output->feature_blocks = feat_blk_list_clone(output->feature_blocks);
  }

  return new_output;
}

void output_alias_print(output_alias_t* output, uint8_t indentation) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("%sAlias Output: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tAmount: %" PRIu64 "\n", PRINT_INDENTATION(indentation), output->amount);

  // print native tokens
  native_tokens_print(&output->native_tokens, indentation + 1);

  // print alias ID
  printf("%s\tAlias ID: ", PRINT_INDENTATION(indentation));
  dump_hex_str(output->alias_id, ADDRESS_ALIAS_BYTES);

  // print state controller
  printf("%s\tState Controller: ", PRINT_INDENTATION(indentation));
  address_print(output->st_ctl);

  // print governance controller
  printf("%s\tGovernance Controller: ", PRINT_INDENTATION(indentation));
  address_print(output->gov_ctl);

  printf("%s\tState Index: %" PRIu32 "\n", PRINT_INDENTATION(indentation), output->state_index);

  // print metadata
  printf("%s\tMetadata: ", PRINT_INDENTATION(indentation));
  if (output->state_metadata) {
    dump_hex_str(output->state_metadata->data, output->state_metadata->len);
  } else {
    printf("%s/\n", PRINT_INDENTATION(indentation));
  }

  printf("%s\tFoundry Counter: %" PRIu32 "\n", PRINT_INDENTATION(indentation), output->foundry_counter);

  // print feature blocks
  feat_blk_list_print(output->feature_blocks, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
