// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"

// maximum number of features
#define MAX_ALIAS_FEATURES_COUNT 2
// maximum number of immutable features
#define MAX_ALIAS_IMMUTABLE_FEATURES_COUNT 2

output_alias_t* output_alias_new(uint64_t amount, native_tokens_list_t* tokens, byte_t alias_id[], uint32_t state_index,
                                 byte_t* metadata, uint32_t metadata_len, uint32_t foundry_counter,
                                 cond_blk_list_t* cond_blocks, feature_list_t* features,
                                 feature_list_t* immut_features) {
  if (alias_id == NULL || cond_blocks == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  // When Alias ID is zeroed out, State Index and Foundry Counter must be 0.
  if (buf_all_zeros(alias_id, ALIAS_ID_BYTES)) {
    if (state_index != 0 || foundry_counter != 0) {
      printf("[%s:%d] when alias ID is zero then state index and foundry counter must be zero\n", __func__, __LINE__);
      return NULL;
    }
  }

  // State Metadata Length must not be greater than Max Metadata Length
  if (metadata_len > MAX_METADATA_LENGTH_BYTES) {
    printf("[%s:%d] Metadata length must not be greater than %d\n", __func__, __LINE__, MAX_METADATA_LENGTH_BYTES);
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
  memcpy(output->alias_id, alias_id, ALIAS_ID_BYTES);

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

  // add features
  output->features = feature_list_clone(features);

  // add immutable features
  output->immutable_features = feature_list_clone(immut_features);

  return output;
}

void output_alias_free(output_alias_t* output) {
  if (output) {
    if (output->native_tokens) {
      native_tokens_free(output->native_tokens);
    }
    byte_buf_free(output->state_metadata);
    cond_blk_list_free(output->unlock_conditions);
    feature_list_free(output->features);
    feature_list_free(output->immutable_features);
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
  length += native_tokens_serialize_len(output->native_tokens);
  // alias ID
  length += ALIAS_ID_BYTES;
  // state index
  length += sizeof(uint32_t);
  // metadata length
  length += sizeof(uint16_t);
  // metadata
  if (output->state_metadata) {
    length += output->state_metadata->len;
  }
  // foundry counter
  length += sizeof(uint32_t);
  // unlock conditions
  length += cond_blk_list_serialize_len(output->unlock_conditions);
  // features
  length += feature_list_serialize_len(output->features);
  // immutable features
  length += feature_list_serialize_len(output->immutable_features);

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
  offset += native_tokens_serialize(&output->native_tokens, buf + offset, buf_len - offset);

  // alias ID
  memcpy(buf + offset, output->alias_id, ALIAS_ID_BYTES);
  offset += ALIAS_ID_BYTES;

  // state index
  memcpy(buf + offset, &output->state_index, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // immutable metadata
  if (output->state_metadata) {
    uint16_t metadata_len = output->state_metadata->len;
    memcpy(buf + offset, &metadata_len, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    memcpy(buf + offset, output->state_metadata->data, metadata_len);
    offset += metadata_len;
  } else {
    memset(buf + offset, 0, sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  // foundry counter
  memcpy(buf + offset, &output->foundry_counter, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // unlock conditions
  offset += cond_blk_list_serialize(&output->unlock_conditions, buf + offset, buf_len - offset);

  // features
  if (output->features) {
    offset += feature_list_serialize(&output->features, buf + offset, buf_len - offset);
  } else {
    memset(buf + offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  // immutable features
  if (output->immutable_features) {
    offset += feature_list_serialize(&output->immutable_features, buf + offset, buf_len - offset);
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
  uint8_t tokens_count = 0;
  memcpy(&tokens_count, &buf[offset], sizeof(uint8_t));
  if (tokens_count > 0) {
    output->native_tokens = native_tokens_deserialize(&buf[offset], buf_len - offset);
    if (!output->native_tokens) {
      printf("[%s:%d] can not deserialize native tokens\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
  }
  offset += native_tokens_serialize_len(output->native_tokens);

  // alias ID
  if (buf_len < offset + ALIAS_ID_BYTES) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  }
  memcpy(&output->alias_id, &buf[offset], ALIAS_ID_BYTES);
  offset += ALIAS_ID_BYTES;

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
  uint16_t metadata_len;
  memcpy(&metadata_len, &buf[offset], sizeof(uint16_t));
  offset += sizeof(uint16_t);

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

  // features
  uint8_t features_count = 0;
  memcpy(&features_count, &buf[offset], sizeof(uint8_t));
  if (features_count > MAX_ALIAS_FEATURES_COUNT) {
    printf("[%s:%d] invalid features count\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  } else if (features_count > 0) {
    output->features = feature_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->features) {
      printf("[%s:%d] can not deserialize features\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    offset += feature_list_serialize_len(output->features);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
  }

  // immutable features
  uint8_t immut_features_count = 0;
  memcpy(&immut_features_count, &buf[offset], sizeof(uint8_t));
  if (immut_features_count > MAX_ALIAS_IMMUTABLE_FEATURES_COUNT) {
    printf("[%s:%d] invalid immutable feature count\n", __func__, __LINE__);
    output_alias_free(output);
    return NULL;
  } else if (immut_features_count > 0) {
    output->immutable_features = feature_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->immutable_features) {
      printf("[%s:%d] can not deserialize immutable features\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    offset += feature_list_serialize_len(output->immutable_features);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_alias_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
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
    memcpy(new_output->alias_id, output->alias_id, ALIAS_ID_BYTES);
    new_output->state_index = output->state_index;
    if (output->state_metadata) {
      new_output->state_metadata = byte_buf_clone(output->state_metadata);
    } else {
      new_output->state_metadata = NULL;
    }
    new_output->foundry_counter = output->foundry_counter;
    new_output->unlock_conditions = cond_blk_list_clone(output->unlock_conditions);
    new_output->features = feature_list_clone(output->features);
    new_output->immutable_features = feature_list_clone(output->immutable_features);
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
  native_tokens_print(output->native_tokens, indentation + 1);

  // print alias ID
  printf("%s\tAlias ID: ", PRINT_INDENTATION(indentation));
  dump_hex_str(output->alias_id, ALIAS_ID_BYTES);

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
  // print features
  feature_list_print(output->features, false, indentation + 1);
  // print immutable features
  feature_list_print(output->immutable_features, true, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}

bool output_alias_syntactic(output_alias_t* output) {
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
  // unlock conditions count == 2
  if (cond_blk_list_len(output->unlock_conditions) != 2) {
    printf("[%s:%d] Unlock condition count must be 2\n", __func__, __LINE__);
    return false;
  }
  // Unlock Condition types:
  // - State Controller Address (mandatory)
  // - Governor Address (mandatory)
  if (cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_STATE) == NULL ||
      cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_GOVERNOR) == NULL) {
    printf("[%s:%d] State Controller Address and Governor Address must be present\n", __func__, __LINE__);
    return false;
  }
  // Unlock Condition must be sorted in ascending order based on their type
  cond_blk_list_sort(&output->unlock_conditions);

  // == Feature Blocks validation ===
  // 0<= features count <= 2
  if (feature_list_len(output->features) > MAX_ALIAS_FEATURES_COUNT) {
    printf("[%s:%d] invalid feature count must smaller than %d\n", __func__, __LINE__, MAX_ALIAS_FEATURES_COUNT);
    return false;
  }
  if (feature_list_len(output->features) > 0) {
    // feature types
    // - Sender
    // - Metadata
    if (feature_list_get_type(output->features, FEAT_ISSUER_TYPE) ||
        feature_list_get_type(output->features, FEAT_TAG_TYPE)) {
      printf("[%s:%d] Issuer and Tag features are not allowed\n", __func__, __LINE__);
      return false;
    }
  }
  // Blocks must stored in ascending order based on their Block Type
  feature_list_sort(&output->features);

  // == Immutable Feature Blocks validation ===
  // 0<= immutable feature count <= 2
  if (feature_list_len(output->immutable_features) > MAX_ALIAS_IMMUTABLE_FEATURES_COUNT) {
    printf("[%s:%d] invalid immutable feature count must smaller than %d\n", __func__, __LINE__,
           MAX_ALIAS_IMMUTABLE_FEATURES_COUNT);
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

  return true;
}
