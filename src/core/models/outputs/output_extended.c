// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/address.h"
#include "core/models/outputs/output_extended.h"
#include "uthash.h"

output_extended_t* output_extended_new(address_t* addr, uint64_t amount, native_tokens_t** tokens,
                                       feat_list_t* feat_blocks) {
  if (addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (amount < 1000000) {
    printf("[%s:%d] dust allowance amount must be at least 1Mi\n", __func__, __LINE__);
    return NULL;
  }

  output_extended_t* output = malloc(sizeof(output_extended_t));
  if (!output) {
    return NULL;
  }

  output->address = malloc(sizeof(address_t));
  if (!output->address) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }

  memcpy(output->address, addr, sizeof(address_t));
  output->amount = amount;

  if (tokens != NULL) {
    output->native_tokens = native_tokens_new();
    native_tokens_t *token, *token_tmp;
    HASH_ITER(hh, *tokens, token, token_tmp) {
      int res = native_tokens_add_from_amount_uint256(&output->native_tokens, token->token_id, token->amount);
      if (res == -1) {
        printf("[%s:%d] can not add native token to extended output\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
    }
  } else {
    output->native_tokens = NULL;
  }

  if (feat_blocks != NULL) {
    output->feature_blocks = NULL;
    while (feat_blocks) {
      feat_list_t* feat_new = malloc(sizeof(feat_list_t));
      if (!feat_new) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        output_extended_free(output);
        return NULL;
      }
      memcpy(&feat_new->blk, &feat_blocks->blk, sizeof(feat_block_t));
      feat_new->next = NULL;

      if (!output->feature_blocks) {
        // if the feature block list is empty, then make the new feature block as head
        output->feature_blocks = feat_new;
      } else {
        // traverse till the last feature block in a list
        feat_list_t* feat_last = output->feature_blocks;
        while (feat_last->next != NULL) {
          feat_last = feat_last->next;
        }
        // change the next feature of currently last feature
        feat_last->next = feat_new;
      }
      feat_blocks = feat_blocks->next;
    }
  } else {
    output->feature_blocks = NULL;
  }

  return output;
}

void output_extended_free(output_extended_t* output) {
  if (output) {
    if (output->address) {
      free(output->address);
    }
    if (output->native_tokens) {
      native_tokens_free(&output->native_tokens);
    }
    feat_list_t* feat_head = output->feature_blocks;
    while (feat_head) {
      feat_list_t* tmp = feat_head;
      feat_head = feat_head->next;
      free_feat_blk(&tmp->blk);
    }
    free(output);
  }
}

size_t output_extended_serialize_len(output_extended_t* output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t length = 0;

  // output type
  length += sizeof(uint8_t);
  // address
  length += address_serialized_len(output->address);
  // amount
  length += sizeof(uint64_t);
  // native tokens
  length += native_tokens_serialize_len(&output->native_tokens);
  // feature blocks count
  length += sizeof(uint8_t);
  // feature blocks
  feat_list_t* feat_elm = output->feature_blocks;
  while (feat_elm != NULL) {
    length += feat_blk_serialize_len(&output->feature_blocks->blk);
    feat_elm = feat_elm->next;
  }

  return length;
}

int output_extended_serialize(output_extended_t* output, byte_t buf[], size_t buf_len) {
  if (output == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (buf_len < output_extended_serialize_len(output)) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return -1;
  }

  byte_t* offset = buf;

  // fill-in output type, set to value 3 to denote a Extended Output
  memset(offset, 3, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // address
  int res = address_serialize(output->address, offset, address_serialized_len(output->address));
  if (res == -1) {
    printf("[%s:%d] can not serialize address\n", __func__, __LINE__);
    return -1;
  }
  offset += address_serialized_len(output->address);

  // amount
  memcpy(offset, &output->amount, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // Native Tokens
  if (output->native_tokens) {
    res = native_tokens_serialize(&output->native_tokens, offset, native_tokens_serialize_len(&output->native_tokens));
    if (res == -1) {
      printf("[%s:%d] can not serialize Native Tokens\n", __func__, __LINE__);
      return -1;
    }
    offset += native_tokens_serialize_len(&output->native_tokens);
  } else {
    memset(offset, 0, sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  // Feature Blocks
  if (output->feature_blocks) {
    // Count Feature Blocks
    uint8_t count = 0;
    feat_list_t* feat_elm = output->feature_blocks;
    while (feat_elm) {
      count += 1;
      feat_elm = feat_elm->next;
    }
    memset(offset, count, sizeof(uint8_t));
    offset += sizeof(uint8_t);

    // Serialize Feature Blocks
    feat_elm = output->feature_blocks;
    while (feat_elm) {
      int res = feat_blk_serialize(&feat_elm->blk, offset, feat_blk_serialize_len(&feat_elm->blk));
      offset += feat_blk_serialize_len(&feat_elm->blk);
      feat_elm = feat_elm->next;
    }
  } else {
    memset(offset, 0, sizeof(uint8_t));
    offset += sizeof(uint8_t);
  }

  return 0;
}

output_extended_t* output_extended_deserialize(byte_t buf[], size_t buf_len) {
  if (!buf || buf_len == 0) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  output_extended_t* output = malloc(sizeof(output_extended_t));
  if (!output) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  output->address = NULL;
  output->native_tokens = NULL;
  output->feature_blocks = NULL;

  size_t offset = 0;

  // output type
  if (buf[offset] != 3) {
    printf("[%s:%d] buffer does not contain Extended Output object\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  offset += sizeof(uint8_t);

  // address
  output->address = malloc(sizeof(address_t));
  if (!output->address) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  if (buf_len < offset + sizeof(uint8_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  output->address->type = buf[offset];
  offset += sizeof(uint8_t);
  if (buf_len < offset + address_serialized_len(output->address) - sizeof(uint8_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  memcpy(output->address->address, &buf[offset], address_serialized_len(output->address) - sizeof(uint8_t));
  offset += address_serialized_len(output->address) - sizeof(uint8_t);

  // amount
  if (buf_len < offset + sizeof(uint64_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  memcpy(&output->amount, &buf[offset], sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // Native Tokens
  if (buf_len < offset + sizeof(uint16_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  uint16_t tokens_count = (uint16_t)buf[offset];
  if (buf_len < offset + sizeof(uint16_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  output->native_tokens =
      native_tokens_deserialize(&buf[offset], sizeof(uint16_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES));
  if (!output->native_tokens) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  offset += sizeof(uint16_t) + (tokens_count * NATIVE_TOKENS_SERIALIZED_BYTES);

  // Feature Blocks
  if (buf_len < offset + sizeof(uint8_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    output_extended_free(output);
    return NULL;
  }
  uint8_t feat_count = buf[offset];
  offset += sizeof(uint8_t);
  for (uint8_t i = 0; i < feat_count; i++) {
    feat_list_t* feat_new = malloc(sizeof(feat_list_t));
    if (!feat_new) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
    }
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
    }
    feat_new->blk.type = buf[offset];
    if (buf_len < offset + 2) {  // TODO fix buffer length
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
    }
    feat_block_t* feat = feat_blk_deserialize(&buf[offset], 100);  // TODO fix buffer length
    if (!feat) {
      printf("[%s:%d] can not deserialize feature block\n", __func__, __LINE__);
      output_extended_free(output);
      return NULL;
    }
    feat_new->blk.block = feat->block;
    offset += feat_blk_serialize_len(&feat_new->blk);
    feat_new->next = NULL;

    if (!output->feature_blocks) {
      // if the feature block list is empty, then make the new feature block as head
      output->feature_blocks = feat_new;
    } else {
      // traverse till the last feature block in a list
      feat_list_t* feat_last = output->feature_blocks;
      while (feat_last->next != NULL) {
        feat_last = feat_last->next;
      }
      // change the next feature of currently last feature
      feat_last->next = feat_new;
    }
  }

  return output;
}

void output_extended_print(output_extended_t* output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }

  printf("Extended Output: [\n");
  printf("\tAddress: ");
  address_print(output->address);
  printf("\tAmmount: %" PRIu64 "\n", output->amount);

  // print Native Tokens
  native_tokens_t *elm, *tmp;
  char* amount_str;

  printf("\tNative Tokens: [\n");
  HASH_ITER(hh, *(&output->native_tokens), elm, tmp) {
    amount_str = uint256_to_str(elm->amount);
    printf("\t\t[%s] ", amount_str);
    dump_hex_str(elm->token_id, NATIVE_TOKEN_ID_BYTES);
    free(amount_str);
  }
  printf("\t]\n");

  // print Feature Blocks
  feat_list_t* feat_elm = output->feature_blocks;
  printf("\tFeature Blocks: [\n");
  while (feat_elm) {
    printf("\t\t");
    feat_blk_print(&feat_elm->blk);
    feat_elm = feat_elm->next;
  }
  printf("\t]\n");

  printf("]\n");
}
