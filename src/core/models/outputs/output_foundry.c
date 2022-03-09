// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/outputs.h"

output_foundry_t* output_foundry_new(address_t* alias, uint64_t amount, native_tokens_t* tokens, uint32_t serial_num,
                                     byte_t token_tag[], uint256_t* circ_supply, uint256_t* max_supply,
                                     token_scheme_e token_scheme, byte_t meta[], size_t meta_len, byte_t immut_meta[],
                                     size_t immut_meta_len) {
  if (!alias || !circ_supply || !max_supply) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // must be an alias address
  if (alias->type != ADDRESS_TYPE_ALIAS) {
    printf("[%s:%d] must be Alias address\n", __func__, __LINE__);
    return NULL;
  }

  // max supply must be larger than zero
  uint256_t* max_supply_check = uint256_from_str("0");
  if (!max_supply_check) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  if (!uint256_equal(max_supply, max_supply_check)) {
    printf("[%s:%d] maximum supply cannot be 0\n", __func__, __LINE__);
    free(max_supply_check);
    return NULL;
  }

  free(max_supply_check);

  if (uint256_equal(circ_supply, max_supply) > 0) {
    printf("[%s:%d] circulating supply must not be greater than maximum supply\n", __func__, __LINE__);
    return NULL;
  }

  // Currently, only SIMPLE_TOKEN_SCHEME is supported
  if (token_scheme != SIMPLE_TOKEN_SCHEME) {
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
  // Copy token tag, 12 bytes
  memcpy(output->token_tag, token_tag, TOKEN_TAG_BYTES_LEN);
  // Store circulating supply of tokens
  memcpy(&output->circ_supply, circ_supply, sizeof(output->circ_supply));
  // Store maximum supply of tokens
  memcpy(&output->max_supply, max_supply, sizeof(output->max_supply));
  // Store token scheme
  output->token_scheme = token_scheme;

  // create address unlock
  unlock_cond_blk_t* addr_unlock = cond_blk_addr_new(alias);
  if (!addr_unlock) {
    printf("[%s:%d] create an address unlock condition error\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  // add address unlock to condition list
  if (cond_blk_list_add(&output->unlock_conditions, addr_unlock) != 0) {
    printf("[%s:%d] can not add unlock conditions to foundry output\n", __func__, __LINE__);
    cond_blk_free(addr_unlock);
    output_foundry_free(output);
    return NULL;
  }
  cond_blk_free(addr_unlock);

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
      native_tokens_free(&output->native_tokens);
    }
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
  length += native_tokens_serialize_len(&output->native_tokens);
  // serial number
  length += sizeof(output->serial);
  // token tag
  length += TOKEN_TAG_BYTES_LEN;
  // circulating supply
  length += sizeof(output->circ_supply);
  // maximum supply
  length += sizeof(output->max_supply);
  // token_scheme
  length += sizeof(uint8_t);
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
  // token tag
  memcpy(buf + offset, output->token_tag, TOKEN_TAG_BYTES_LEN);
  offset += TOKEN_TAG_BYTES_LEN;
  // circulating supply
  memcpy(buf + offset, &output->circ_supply, sizeof(output->circ_supply));
  offset += sizeof(output->circ_supply);
  // maximum supply
  memcpy(buf + offset, &output->max_supply, sizeof(output->max_supply));
  offset += sizeof(output->max_supply);
  // token scheme
  memcpy(buf + offset, &output->token_scheme, sizeof(uint8_t));
  offset += sizeof(uint8_t);
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
  offset += native_tokens_serialize_len(&output->native_tokens);

  // serial number
  if (buf_len < offset + sizeof(output->serial)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->serial, &buf[offset], sizeof(output->serial));
  offset += sizeof(output->serial);

  // token tag
  if (buf_len < offset + TOKEN_TAG_BYTES_LEN) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->token_tag, &buf[offset], TOKEN_TAG_BYTES_LEN);
  offset += TOKEN_TAG_BYTES_LEN;

  // circulating supply
  if (buf_len < offset + sizeof(output->circ_supply)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->circ_supply, &buf[offset], sizeof(output->circ_supply));
  offset += sizeof(output->circ_supply);

  // maximum supply
  if (buf_len < offset + sizeof(output->max_supply)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->max_supply, &buf[offset], sizeof(output->max_supply));
  offset += sizeof(output->max_supply);

  // token scheme
  if (buf_len < offset + sizeof(uint8_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_foundry_free(output);
    return NULL;
  }
  memcpy(&output->token_scheme, &buf[offset], sizeof(uint8_t));
  offset += sizeof(uint8_t);

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
    memcpy(new_output->token_tag, output->token_tag, TOKEN_TAG_BYTES_LEN);
    memcpy(&new_output->circ_supply, &output->circ_supply, sizeof(output->circ_supply));
    memcpy(&new_output->max_supply, &output->max_supply, sizeof(output->max_supply));
    new_output->token_scheme = output->token_scheme;
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
  native_tokens_print(&output->native_tokens, indentation + 1);

  printf("%s\tSerial Number: %" PRIu32 "\n", PRINT_INDENTATION(indentation), output->serial);

  // print token tag
  printf("%s\tToken Tag: ", PRINT_INDENTATION(indentation));
  dump_hex_str(output->token_tag, TOKEN_TAG_BYTES_LEN);

  // print circulating supply
  char* circ_supply_str;
  circ_supply_str = uint256_to_str(&output->circ_supply);
  if (circ_supply_str != NULL) {
    printf("%s\tCirculating Supply: [%s]\n", PRINT_INDENTATION(indentation), circ_supply_str);
    free(circ_supply_str);
  }

  // print maximum supply
  char* max_supply_str;
  max_supply_str = uint256_to_str(&output->max_supply);
  if (max_supply_str != NULL) {
    printf("%s\tMaximum Supply: [%s]\n", PRINT_INDENTATION(indentation), max_supply_str);
    free(max_supply_str);
  }

  token_scheme_e token_scheme = output->token_scheme;
  if (token_scheme == SIMPLE_TOKEN_SCHEME) {
    printf("%s\tToken Scheme: Simple Token Scheme\n", PRINT_INDENTATION(indentation));
  } else {
    printf("%s\tToken Scheme: Unknown Token Scheme\n", PRINT_INDENTATION(indentation));
  }

  // print unlock conditions
  cond_blk_list_print(output->unlock_conditions, indentation + 1);
  // print feature blocks
  feat_blk_list_print(output->feature_blocks, false, indentation + 1);
  // print immutable feature blocks
  feat_blk_list_print(output->immutable_blocks, true, indentation + 1);

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
