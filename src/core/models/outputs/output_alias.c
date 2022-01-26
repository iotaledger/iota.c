// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/address.h"
#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/outputs.h"
#include "uthash.h"
#include "utlist.h"

// maximum number of feature blocks
#define MAX_ALIAS_FEATURE_BLOCKS_COUNT 3

output_alias_t* output_alias_new(uint64_t amount, native_tokens_t* tokens, byte_t alias_id[], uint32_t state_index,
                                 byte_t* metadata, uint32_t metadata_len, uint32_t foundry_counter,
                                 cond_blk_list_t* cond_blocks, feat_blk_list_t* feat_blocks) {
  if (alias_id == NULL || cond_blocks == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  // FIXME: amount must fulfill the Byte Cost Dust Protection
  // if (amount < MIN_DUST_ALLOWANCE) {
  //   printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
  //   return NULL;
  // }

  // Unlock condition count must be 2
  if (cond_blk_list_len(cond_blocks) != 2) {
    printf("[%s:%d] Unlock condition count must be 2\n", __func__, __LINE__);
    return NULL;
  } else {
    // unlock condition must be UNLOCK_COND_STATE and UNLOCK_COND_GOVERNOR
    if (!cond_blk_list_get_type(cond_blocks, UNLOCK_COND_STATE) ||
        !cond_blk_list_get_type(cond_blocks, UNLOCK_COND_GOVERNOR)) {
      printf("[%s:%d] Unlock condition must be State Controller and Governor\n", __func__, __LINE__);
      return NULL;
    }
  }

  // 0<= Feature block count <= 3
  if (feat_blk_list_len(feat_blocks) > MAX_ALIAS_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] there should be at most %d feature blocks\n", __func__, __LINE__, MAX_ALIAS_FEATURE_BLOCKS_COUNT);
    return NULL;
  }

  // When Alias ID is zeroed out, State Index and Foundry Counter must be 0.
  if (buf_all_zeros(alias_id, ADDRESS_ALIAS_BYTES)) {
    if (state_index != 0 || foundry_counter != 0) {
      printf("[%s:%d] when alias ID is zero then state index and foundry counter must be zero\n", __func__, __LINE__);
      return NULL;
    }
  }

  // State Metadata Length must not be greater than Max Metadata Length
  if (metadata_len > MAX_METADATA_LENGTH_BYTES) {
    printf("[%s:%d] Metadata length must no be greater than %d\n", __func__, __LINE__, MAX_METADATA_LENGTH_BYTES);
    return NULL;
  }

  output_alias_t* output = malloc(sizeof(output_alias_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  // init the alias object
  memset(output, 0, sizeof(output_alias_t));

  // amount
  output->amount = amount;

  // native tokens
  output->native_tokens = native_tokens_clone(tokens);

  // alias ID
  memcpy(output->alias_id, alias_id, ADDRESS_ALIAS_BYTES);

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

  // add condition blocks
  output->unlock_conditions = cond_blk_list_clone(cond_blocks);
  if (!output->unlock_conditions) {
    printf("[%s:%d] can not add unlock conditions to Alias output\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }

  // add feature blocks
  output->feature_blocks = feat_blk_list_clone(feat_blocks);

  return output;
}

void output_alias_free(output_alias_t* output) {
  if (output) {
    if (output->native_tokens) {
      native_tokens_free(&output->native_tokens);
    }
    byte_buf_free(output->state_metadata);
    cond_blk_list_free(output->unlock_conditions);
    feat_blk_list_free(output->feature_blocks);
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
  // unlock conditions
  length += cond_blk_list_serialize_len(output->unlock_conditions);
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

  size_t offset = 0;

  // fill-in Alias Output type
  memset(buf, OUTPUT_ALIAS, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // amount
  memcpy(buf + offset, &output->amount, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // native tokens
  // TODO? native token serialize with empty list
  if (output->native_tokens) {
    offset += native_tokens_serialize(&output->native_tokens, buf + offset, buf_len - offset);
  } else {
    memset(buf + offset, 0, sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  // alias ID
  memcpy(buf + offset, output->alias_id, ADDRESS_ALIAS_BYTES);
  offset += ADDRESS_ALIAS_BYTES;

  // state index
  memcpy(buf + offset, &output->state_index, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // immutable metadata
  if (output->state_metadata) {
    uint32_t metadata_len = output->state_metadata->len;
    memcpy(buf + offset, &metadata_len, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(buf + offset, output->state_metadata->data, metadata_len);
    offset += metadata_len;
  } else {
    memset(buf + offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
  }

  // foundry counter
  memcpy(buf + offset, &output->foundry_counter, sizeof(uint32_t));
  offset += sizeof(uint32_t);

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

output_alias_t* output_alias_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_alias_t* output = malloc(sizeof(output_alias_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  // init alias object
  memset(output, 0, sizeof(output_alias_t));

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

  // unlock condition blocks
  uint8_t unlock_count = 0;
  memcpy(&unlock_count, &buf[offset], sizeof(uint8_t));
  if (unlock_count != 2) {
    printf("[%s:%d] invalid unlock block count\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  } else {
    output->unlock_conditions = cond_blk_list_deserialize(buf + offset, buf_len - offset);
    if (!output->unlock_conditions) {
      printf("[%s:%d] can not deserialize unlock conditions\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    offset += cond_blk_list_serialize_len(output->unlock_conditions);
  }

  // feature blocks
  uint8_t feat_block_count = 0;
  memcpy(&feat_block_count, &buf[offset], sizeof(uint8_t));
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
    new_output->state_index = output->state_index;
    new_output->state_metadata = byte_buf_clone(output->state_metadata);
    new_output->foundry_counter = output->foundry_counter;
    new_output->unlock_conditions = cond_blk_list_clone(output->unlock_conditions);
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

  printf("%s\tState Index: %" PRIu32 "\n", PRINT_INDENTATION(indentation), output->state_index);

  // print metadata
  printf("%s\tMetadata: ", PRINT_INDENTATION(indentation));
  if (output->state_metadata) {
    dump_hex_str(output->state_metadata->data, output->state_metadata->len);
  } else {
    printf("%s\n", PRINT_INDENTATION(indentation));
  }

  printf("%s\tFoundry Counter: %" PRIu32 "\n", PRINT_INDENTATION(indentation), output->foundry_counter);

  // print unlock condition blocks
  cond_blk_list_print(output->unlock_conditions, indentation + 1);
  // print feature blocks
  feat_blk_list_print(output->feature_blocks, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
