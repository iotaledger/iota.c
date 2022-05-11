// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/models/outputs/outputs.h"
#include "core/utils/macros.h"

// maximum number of unlock condition blocks
#define MAX_FOUNDRY_CONDITION_BLOCKS_COUNT 1
// maximum number of feature blocks
#define MAX_FOUNDRY_FEATURE_BLOCKS_COUNT 1
// maximum number of immutable feature blocks
#define MAX_FOUNDRY_IMMUTABLE_BLOCKS_COUNT 1

static token_scheme_simple_t* simple_token_scheme_new(uint256_t* minted_tokens, uint256_t* melted_tokens,
                                                      uint256_t* max_supply) {
  if (!minted_tokens || !melted_tokens || !max_supply) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  token_scheme_simple_t* scheme = malloc(sizeof(token_scheme_simple_t));
  if (scheme) {
    memcpy(&scheme->minted_tokens, minted_tokens, sizeof(scheme->minted_tokens));
    memcpy(&scheme->melted_tokens, melted_tokens, sizeof(scheme->melted_tokens));
    memcpy(&scheme->max_supply, max_supply, sizeof(scheme->max_supply));
  }

  return scheme;
}

token_scheme_t* token_scheme_simple_new(uint256_t* minted_tokens, uint256_t* melted_tokens, uint256_t* max_supply) {
  token_scheme_t* scheme = malloc(sizeof(token_scheme_t));
  if (scheme) {
    scheme->token_scheme = simple_token_scheme_new(minted_tokens, melted_tokens, max_supply);
    if (!scheme->token_scheme) {
      free(scheme);
      return NULL;
    }
    scheme->type = SIMPLE_TOKEN_SCHEME;
  }
  return scheme;
}

token_scheme_t* token_scheme_clone(token_scheme_t* scheme) {
  if (!scheme) {
    return NULL;
  }

  token_scheme_t* new_scheme = malloc(sizeof(token_scheme_t));
  if (!new_scheme) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  // Currently on simple token scheme is supported
  if (scheme->type == SIMPLE_TOKEN_SCHEME) {
    token_scheme_simple_t* simple_scheme = scheme->token_scheme;
    new_scheme->token_scheme = simple_token_scheme_new(&simple_scheme->minted_tokens, &simple_scheme->melted_tokens,
                                                       &simple_scheme->max_supply);
    if (!new_scheme->token_scheme) {
      free(new_scheme);
      return NULL;
    }
    new_scheme->type = SIMPLE_TOKEN_SCHEME;
  } else {
    printf("[%s:%d] unknown token scheme type\n", __func__, __LINE__);
    free(new_scheme);
    return NULL;
  }
  return new_scheme;
}

size_t token_scheme_serialize_len(token_scheme_t* scheme) {
  if (!scheme) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }
  size_t len = 0;
  // Currently only simple token scheme is supported
  if (scheme->type == SIMPLE_TOKEN_SCHEME) {
    // token scheme type
    len += sizeof(uint8_t);
    // minted tokens
    len += sizeof(uint256_t);
    // melted tokens
    len += sizeof(uint256_t);
    // max supply
    len += sizeof(uint256_t);
  }
  return len;
}

size_t token_scheme_serialize(token_scheme_t* scheme, byte_t buf[], size_t buf_len) {
  if (!scheme || !buf || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;
  size_t expected_bytes = token_scheme_serialize_len(scheme);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  // fillin token scheme type
  memcpy(buf, &scheme->type, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  if (scheme->type == SIMPLE_TOKEN_SCHEME) {
    token_scheme_simple_t* simple_token_scheme = scheme->token_scheme;
    memcpy(buf + offset, &simple_token_scheme->minted_tokens, sizeof(simple_token_scheme->minted_tokens));
    offset += sizeof(simple_token_scheme->minted_tokens);
    memcpy(buf + offset, &simple_token_scheme->melted_tokens, sizeof(simple_token_scheme->melted_tokens));
    offset += sizeof(simple_token_scheme->melted_tokens);
    memcpy(buf + offset, &simple_token_scheme->max_supply, sizeof(simple_token_scheme->max_supply));
    offset += sizeof(simple_token_scheme->max_supply);
    return offset;
  } else {
    printf("[%s:%d] unknown token scheme type\n", __func__, __LINE__);
  }
  return 0;
}

token_scheme_t* token_scheme_deserialize(byte_t buf[], size_t buf_len) {
  token_scheme_t* scheme = malloc(sizeof(token_scheme_t));
  if (!scheme) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  size_t offset = 0;
  scheme->type = buf[offset];
  offset += sizeof(uint8_t);
  if (scheme->type == SIMPLE_TOKEN_SCHEME) {
    if (buf_len < token_scheme_serialize_len(scheme)) {
      printf("[%s:%d] insufficient buffer size\n", __func__, __LINE__);
      free(scheme);
      return NULL;
    }
    token_scheme_simple_t* simple_token_scheme = malloc(sizeof(token_scheme_simple_t));
    memcpy(&simple_token_scheme->minted_tokens, buf + offset, sizeof(simple_token_scheme->minted_tokens));
    offset += sizeof(simple_token_scheme->minted_tokens);
    memcpy(&simple_token_scheme->melted_tokens, buf + offset, sizeof(simple_token_scheme->melted_tokens));
    offset += sizeof(simple_token_scheme->melted_tokens);
    memcpy(&simple_token_scheme->max_supply, buf + offset, sizeof(simple_token_scheme->max_supply));
    offset += sizeof(simple_token_scheme->max_supply);

    scheme->token_scheme = simple_token_scheme;
    return scheme;
  } else {
    printf("[%s:%d] unknown token scheme type\n", __func__, __LINE__);
    free(scheme);
  }
  return NULL;
}

bool token_scheme_syntactic(token_scheme_t* token_scheme) {
  if (!token_scheme) {
    printf("[%s:%d] token scheme is null\n", __func__, __LINE__);
    return false;
  }

  if (token_scheme->type != SIMPLE_TOKEN_SCHEME) {
    printf("[%s:%d] unsupported token scheme type\n", __func__, __LINE__);
    return false;
  }

  token_scheme_simple_t* simple_scheme = token_scheme->token_scheme;
  if (!simple_scheme) {
    printf("[%s:%d] simple token scheme is null\n", __func__, __LINE__);
    return false;
  }

  // melted tokens must not be greater than minted tokens
  if (uint256_equal(&simple_scheme->melted_tokens, &simple_scheme->minted_tokens) > 0) {
    printf("[%s:%d] melted tokens must not be greater than minted tokens\n", __func__, __LINE__);
    return false;
  }

  // maximum supply must be larger than zero
  uint256_t* max_supply_check = uint256_from_str("0");
  if (!max_supply_check) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return false;
  }
  if (!uint256_equal(&simple_scheme->max_supply, max_supply_check)) {
    printf("[%s:%d] maximum supply cannot be 0\n", __func__, __LINE__);
    uint256_free(max_supply_check);
    return false;
  }
  uint256_free(max_supply_check);

  uint256_t diff;
  // minted mokens - melted tokens must not be greater than maximum supply.
  bool res = uint256_sub(&diff, &simple_scheme->minted_tokens, &simple_scheme->melted_tokens);
  if (res == false) {
    printf("[%s:%d] uint256 sub failed\n", __func__, __LINE__);
    return false;
  }

  if (uint256_equal(&diff, &simple_scheme->max_supply) > 0) {
    printf("[%s:%d] difference of minted and melted tokens must not be greater than maximum supply\n", __func__,
           __LINE__);
    return false;
  }
  return true;
}

void token_scheme_free(token_scheme_t* scheme) {
  if (scheme) {
    if (scheme->type == SIMPLE_TOKEN_SCHEME) {
      free(scheme->token_scheme);
    }
    free(scheme);
  }
}

void token_scheme_print(token_scheme_t* scheme, uint8_t indentation) {
  if (scheme == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  // Currently only simple token scheme is supported
  if (scheme->type == SIMPLE_TOKEN_SCHEME) {
    printf("%s\tType: [%d]\n", PRINT_INDENTATION(indentation), SIMPLE_TOKEN_SCHEME);
    token_scheme_simple_t* simple_scheme = scheme->token_scheme;
    // print minted tokens
    char* minted_token_str;
    minted_token_str = uint256_to_str(&simple_scheme->minted_tokens);
    if (minted_token_str != NULL) {
      printf("%s\tMinted Tokens: [%s]\n", PRINT_INDENTATION(indentation), minted_token_str);
      free(minted_token_str);
    }
    // print melted tokens
    char* melted_token_str;
    melted_token_str = uint256_to_str(&simple_scheme->melted_tokens);
    if (melted_token_str != NULL) {
      printf("%s\tMelted Tokens: [%s]\n", PRINT_INDENTATION(indentation), melted_token_str);
      free(melted_token_str);
    }
    // print maximum supply
    char* max_supply_str;
    max_supply_str = uint256_to_str(&simple_scheme->max_supply);
    if (max_supply_str != NULL) {
      printf("%s\tMaximum Supply: [%s]\n", PRINT_INDENTATION(indentation), max_supply_str);
      free(max_supply_str);
    }
  }
}

output_foundry_t* output_foundry_new(address_t* alias, uint64_t amount, native_tokens_list_t* tokens,
                                     uint32_t serial_num, token_scheme_t* token_scheme, byte_t meta[], size_t meta_len,
                                     byte_t immut_meta[], size_t immut_meta_len) {
  if (!alias || !token_scheme) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // must be an alias address
  if (alias->type != ADDRESS_TYPE_ALIAS) {
    printf("[%s:%d] must be Alias address\n", __func__, __LINE__);
    return NULL;
  }

  // Currently, only SIMPLE_TOKEN_SCHEME is supported
  if (token_scheme->type != SIMPLE_TOKEN_SCHEME) {
    printf("[%s:%d] token scheme not supported\n", __func__, __LINE__);
    return NULL;
  }

  // Allocate foundry output object
  output_foundry_t* output = malloc(sizeof(output_foundry_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  memset(output, 0, sizeof(output_foundry_t));

  // Store amount
  output->amount = amount;

  // Store native tokens
  if (tokens != NULL) {
    output->native_tokens = native_tokens_clone(tokens);
    if (!output->native_tokens) {
      printf("[%s:%d] can not add native token to foundry output\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
  }

  // Store serial number
  output->serial = serial_num;
  // Add token scheme
  output->token_scheme = token_scheme_clone(token_scheme);

  // create immutable alias address unlock
  unlock_cond_blk_t* immut_unlock = cond_blk_immut_alias_new(alias);
  if (!immut_unlock) {
    printf("[%s:%d] create an address unlock condition error\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  // add unlock condition to list
  if (cond_blk_list_add(&output->unlock_conditions, immut_unlock) != 0) {
    printf("[%s:%d] can not add unlock conditions to foundry output\n", __func__, __LINE__);
    cond_blk_free(immut_unlock);
    output_foundry_free(output);
    return NULL;
  }
  cond_blk_free(immut_unlock);

  if (meta && meta_len > 0) {
    // create metadata block
    if (feat_blk_list_add_metadata(&output->feature_blocks, meta, meta_len) != 0) {
      printf("[%s:%d] can not add feature block to Foundry output\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
  }

  if (immut_meta && immut_meta_len > 0) {
    // create immutable metadata block
    if (feat_blk_list_add_metadata(&output->immutable_blocks, immut_meta, immut_meta_len) != 0) {
      printf("[%s:%d] can not add immutable feature block to Foundry output\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
  }
  return output;
}

void output_foundry_free(output_foundry_t* output) {
  if (output) {
    if (output->native_tokens) {
      native_tokens_free(output->native_tokens);
    }
    token_scheme_free(output->token_scheme);
    cond_blk_list_free(output->unlock_conditions);
    feat_blk_list_free(output->feature_blocks);
    feat_blk_list_free(output->immutable_blocks);
    free(output);
  }
}

size_t output_foundry_serialize_len(output_foundry_t* output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t length = 0;

  // output type
  length += sizeof(uint8_t);
  // amount
  length += sizeof(output->amount);
  // native tokens
  length += native_tokens_serialize_len(output->native_tokens);
  // serial number
  length += sizeof(output->serial);
  // token_scheme
  length += token_scheme_serialize_len(output->token_scheme);
  // unlock conditions
  length += cond_blk_list_serialize_len(output->unlock_conditions);
  // feature blocks
  length += feat_blk_list_serialize_len(output->feature_blocks);
  // immutable feature blocks
  length += feat_blk_list_serialize_len(output->immutable_blocks);

  return length;
}

size_t output_foundry_serialize(output_foundry_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = output_foundry_serialize_len(output);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;
  // fill-in Foundry Output type
  memset(buf + offset, OUTPUT_FOUNDRY, sizeof(uint8_t));
  offset += sizeof(uint8_t);
  // amount
  memcpy(buf + offset, &output->amount, sizeof(output->amount));
  offset += sizeof(output->amount);

  // native tokens
  offset += native_tokens_serialize(&output->native_tokens, buf + offset, buf_len - offset);

  // serial number
  memcpy(buf + offset, &output->serial, sizeof(output->serial));
  offset += sizeof(output->serial);
  // token scheme
  offset += token_scheme_serialize(output->token_scheme, buf + offset, buf_len - offset);
  // condition blocks
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

output_foundry_t* output_foundry_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  output_foundry_t* output = malloc(sizeof(output_foundry_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  memset(output, 0, sizeof(output_foundry_t));

  size_t offset = 0;
  // Check if output type is foundry output
  if (buf[offset] != OUTPUT_FOUNDRY) {
    printf("[%s:%d] buffer does not contain Foundry Output object\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // amount
  if (buf_len < offset + sizeof(output->amount)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->amount, &buf[offset], sizeof(output->amount));
  offset += sizeof(output->amount);

  // native tokens
  uint8_t tokens_count = 0;
  memcpy(&tokens_count, &buf[offset], sizeof(uint8_t));
  if (tokens_count > 0) {
    output->native_tokens = native_tokens_deserialize(&buf[offset], buf_len - offset);
    if (!output->native_tokens) {
      printf("[%s:%d] can not deserialize native tokens\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
  }
  offset += native_tokens_serialize_len(output->native_tokens);

  // serial number
  if (buf_len < offset + sizeof(output->serial)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->serial, &buf[offset], sizeof(output->serial));
  offset += sizeof(output->serial);

  // token scheme
  output->token_scheme = token_scheme_deserialize(&buf[offset], buf_len - offset);
  if (!output->token_scheme) {
    printf("[%s:%d] can not deserialize token scheme\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  offset += token_scheme_serialize_len(output->token_scheme);

  // unlock condition blocks
  uint8_t unlock_count = 0;
  memcpy(&unlock_count, &buf[offset], sizeof(uint8_t));
  if (unlock_count != 1) {
    printf("[%s:%d] invalid unlock block count\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  } else {
    output->unlock_conditions = cond_blk_list_deserialize(buf + offset, buf_len - offset);
    if (!output->unlock_conditions) {
      printf("[%s:%d] can not deserialize unlock conditions\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
    offset += cond_blk_list_serialize_len(output->unlock_conditions);
  }

  // feature blocks
  uint8_t feat_block_count = 0;
  memcpy(&feat_block_count, &buf[offset], sizeof(uint8_t));
  if (feat_block_count > 1) {
    printf("[%s:%d] invalid feature block count\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  } else if (feat_block_count > 0) {
    output->feature_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->feature_blocks) {
      printf("[%s:%d] can not deserialize feature blocks\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
    offset += feat_blk_list_serialize_len(output->feature_blocks);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
  }

  // immutable feature blocks
  uint8_t immut_feat_block_count = 0;
  memcpy(&immut_feat_block_count, &buf[offset], sizeof(uint8_t));
  if (immut_feat_block_count > 1) {
    printf("[%s:%d] invalid immutable feature block count\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  } else if (immut_feat_block_count > 0) {
    output->immutable_blocks = feat_blk_list_deserialize(&buf[offset], buf_len - offset);
    if (!output->immutable_blocks) {
      printf("[%s:%d] can not deserialize immutable feature blocks\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
    offset += feat_blk_list_serialize_len(output->immutable_blocks);
  } else {
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_foundry_free(output);
      return NULL;
    }
    offset += sizeof(uint8_t);
  }

  return output;
}

output_foundry_t* output_foundry_clone(output_foundry_t const* const output) {
  if (output == NULL) {
    return NULL;
  }

  output_foundry_t* new_output = malloc(sizeof(output_foundry_t));
  if (new_output) {
    new_output->amount = output->amount;
    new_output->native_tokens = native_tokens_clone(output->native_tokens);
    new_output->serial = output->serial;
    new_output->token_scheme = token_scheme_clone(output->token_scheme);
    new_output->unlock_conditions = cond_blk_list_clone(output->unlock_conditions);
    new_output->feature_blocks = feat_blk_list_clone(output->feature_blocks);
    new_output->immutable_blocks = feat_blk_list_clone(output->immutable_blocks);
  }

  return new_output;
}

void output_foundry_print(output_foundry_t* output, uint8_t indentation) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("%sFoundry Output: [\n", PRINT_INDENTATION(indentation));

  printf("%s\tAmount: %" PRIu64 "\n", PRINT_INDENTATION(indentation), output->amount);

  // print native tokens
  native_tokens_print(output->native_tokens, indentation + 1);

  printf("%s\tSerial Number: %" PRIu32 "\n", PRINT_INDENTATION(indentation), output->serial);

  // print token scheme
  token_scheme_print(output->token_scheme, indentation + 1);

  // print unlock conditions
  cond_blk_list_print(output->unlock_conditions, indentation + 1);
  // print feature blocks
  feat_blk_list_print(output->feature_blocks, false, indentation + 1);
  // print immutable feature blocks
  feat_blk_list_print(output->immutable_blocks, true, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}

bool output_foundry_syntactic(output_foundry_t* output) {
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

  // Token scheme type should be a Simple Token Scheme which has value 0
  // Minted Tokens - Melted Tokens must not be greater than Maximum Supply
  // Melted Tokens must not be greater than Minted Tokens
  // Maximum Supply must be larger than zero
  if (!token_scheme_syntactic(output->token_scheme)) {
    return false;
  }

  // == Unlock condition validation ===
  // unlock conditions count == 1
  if (cond_blk_list_len(output->unlock_conditions) != MAX_FOUNDRY_CONDITION_BLOCKS_COUNT) {
    printf("[%s:%d] Unlock condition count must be %d\n", __func__, __LINE__, MAX_FOUNDRY_CONDITION_BLOCKS_COUNT);
    return false;
  }
  // Unlock Condition types:
  // - Immutable Alias Address (mandatory)
  if (cond_blk_list_get_type(output->unlock_conditions, UNLOCK_COND_IMMUT_ALIAS) == NULL) {
    printf("[%s:%d] Immutable Alias Address must be present\n", __func__, __LINE__);
    return false;
  }
  // Unlock Condition must be sorted in ascending order based on their type
  // must be only 1 condition, therefore we don't do sorting
  // cond_blk_list_sort(&output->unlock_conditions);

  // == Feature Blocks validation ===
  // 0<= feature block count <= 1
  if (feat_blk_list_len(output->feature_blocks) > MAX_FOUNDRY_FEATURE_BLOCKS_COUNT) {
    printf("[%s:%d] invalid feature block count must smaller than %d\n", __func__, __LINE__,
           MAX_FOUNDRY_CONDITION_BLOCKS_COUNT);
    return false;
  }
  if (feat_blk_list_len(output->feature_blocks) > 0) {
    // feature block types
    // - Metadata
    if (feat_blk_list_get_type(output->feature_blocks, FEAT_METADATA_BLOCK) == NULL) {
      printf("[%s:%d] must be Metadata block\n", __func__, __LINE__);
      return false;
    }
  }
  // Blocks must stored in ascending order based on their Block Type
  // must be only 1 block, therefore we don't do sorting
  // feat_blk_list_sort(&output->feature_blocks);

  // == Immutable Feature Blocks validation ===
  // 0<= immutable block count <= 1
  if (feat_blk_list_len(output->immutable_blocks) > MAX_FOUNDRY_IMMUTABLE_BLOCKS_COUNT) {
    printf("[%s:%d] invalid feature block count must smaller than %d\n", __func__, __LINE__,
           MAX_FOUNDRY_CONDITION_BLOCKS_COUNT);
    return false;
  }
  if (feat_blk_list_len(output->immutable_blocks) > 0) {
    // immutable block types
    // - Metadata
    if (feat_blk_list_get_type(output->immutable_blocks, FEAT_METADATA_BLOCK) == NULL) {
      printf("[%s:%d] must be Metadata Immutable block\n", __func__, __LINE__);
      return false;
    }
  }

  // Blocks must stored in ascending order based on their Block Type
  // must be only 1 block, therefore we don't do sorting
  // feat_blk_list_sort(&output->immutable_blocks);

  return true;
}
