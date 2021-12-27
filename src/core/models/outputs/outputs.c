// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/models/outputs/output_alias.h"
#include "core/models/outputs/output_extended.h"
#include "core/models/outputs/output_foundry.h"
#include "core/models/outputs/output_nft.h"
#include "core/models/outputs/outputs.h"
#include "utlist.h"

#define UTXO_OUTPUT_MAX_COUNT 127

utxo_outputs_list_t *utxo_outputs_new() { return NULL; }

void utxo_outputs_free(utxo_outputs_list_t *outputs) {
  if (outputs) {
    utxo_outputs_list_t *elm, *tmp;
    LL_FOREACH_SAFE(outputs, elm, tmp) {
      switch (elm->output->output_type) {
        case OUTPUT_EXTENDED:
          output_extended_free(elm->output->output);
          break;
        case OUTPUT_ALIAS:
          output_alias_free(elm->output->output);
          break;
        case OUTPUT_FOUNDRY:
          output_foundry_free(elm->output->output);
          break;
        case OUTPUT_NFT:
          output_nft_free(elm->output->output);
          break;
      }
      free(elm->output);
      LL_DELETE(outputs, elm);
      free(elm);
    }
  }
}

int utxo_outputs_add(utxo_outputs_list_t **outputs, utxo_output_type_t type, void *output) {
  if (output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (utxo_outputs_count(*outputs) >= UTXO_OUTPUT_MAX_COUNT) {
    printf("[%s:%d] output count must be <= 127\n", __func__, __LINE__);
    return -1;
  }

  utxo_outputs_list_t *next = malloc(sizeof(utxo_outputs_list_t));
  if (next) {
    next->output = malloc(sizeof(utxo_output_t));
    if (next->output) {
      next->output->output_type = type;
      switch (next->output->output_type) {
        case OUTPUT_EXTENDED:
          next->output->output = malloc(sizeof(output_extended_t));
          memcpy(next->output->output, output, sizeof(output_extended_t));
          break;
        case OUTPUT_ALIAS:
          next->output->output = malloc(sizeof(output_alias_t));
          memcpy(next->output->output, output, sizeof(output_alias_t));
          break;
        case OUTPUT_FOUNDRY:
          next->output->output = malloc(sizeof(output_foundry_t));
          memcpy(next->output->output, output, sizeof(output_foundry_t));
          break;
        case OUTPUT_NFT:
          next->output->output = malloc(sizeof(output_nft_t));
          memcpy(next->output->output, output, sizeof(output_nft_t));
          break;
      }
      if (next->output->output) {
        LL_APPEND(*outputs, next);
        return 0;
      } else {
        free(next);
      }
    }
  }

  return -1;
}

uint16_t utxo_outputs_count(utxo_outputs_list_t *outputs) {
  utxo_outputs_list_t *elm = NULL;
  uint16_t len = 0;
  if (outputs) {
    LL_COUNT(outputs, elm, len);
    return len;
  }
  return len;
}

utxo_output_t *utxo_outputs_get(utxo_outputs_list_t *outputs, uint16_t index) {
  uint16_t count = 0;
  utxo_outputs_list_t *elm;
  if (outputs) {
    LL_FOREACH(outputs, elm) {
      if (count == index) {
        return elm->output;
      }
      count++;
    }
  }
  return NULL;
}

size_t utxo_outputs_serialize_len(utxo_outputs_list_t *outputs) {
  if (outputs == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t len = 0;

  // Outputs layout: Outputs Count + Outputs
  // uint16_t is a number of output entries
  len += sizeof(uint16_t);

  utxo_outputs_list_t *elm;
  size_t output_len;
  LL_FOREACH(outputs, elm) {
    switch (elm->output->output_type) {
      case OUTPUT_EXTENDED:
        output_len = output_extended_serialize_len(elm->output->output);
        break;
      case OUTPUT_ALIAS:
        output_len = output_alias_serialize_len(elm->output->output);
        break;
      case OUTPUT_FOUNDRY:
        output_len = output_foundry_serialize_len(elm->output->output);
        break;
      case OUTPUT_NFT:
        output_len = output_nft_serialize_len(elm->output->output);
        break;
    }
    if (output_len == 0) {
      printf("[%s:%d] can not get outputs serialized len\n", __func__, __LINE__);
      return 0;
    }
    len += output_len;
  }

  return len;
}

size_t utxo_outputs_serialize(utxo_outputs_list_t *outputs, byte_t buf[], size_t buf_len) {
  if (outputs == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = utxo_outputs_serialize_len(outputs);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }
  if (expected_bytes == 0) {
    printf("[%s:%d] outputs serialized length is zero\n", __func__, __LINE__);
    return 0;
  }

  byte_t *offset = buf;

  // number of outputs entries
  uint16_t output_count = utxo_outputs_count(outputs);
  memcpy(offset, &output_count, sizeof(uint16_t));
  offset += sizeof(uint16_t);

  // outputs
  utxo_outputs_list_t *elm;
  LL_FOREACH(outputs, elm) {
    switch (elm->output->output_type) {
      case OUTPUT_EXTENDED:
        offset +=
            output_extended_serialize(elm->output->output, offset, output_extended_serialize_len(elm->output->output));
        break;
      case OUTPUT_ALIAS:
        offset += output_alias_serialize(elm->output->output, offset, output_alias_serialize_len(elm->output->output));
        break;
      case OUTPUT_FOUNDRY:
        offset +=
            output_foundry_serialize(elm->output->output, offset, output_foundry_serialize_len(elm->output->output));
        break;
      case OUTPUT_NFT:
        offset += output_nft_serialize(elm->output->output, offset, output_nft_serialize_len(elm->output->output));
        break;
    }
  }

  return expected_bytes;
}

void utxo_outputs_print(utxo_outputs_list_t *outputs, uint8_t indentation) {
  utxo_outputs_list_t *elm;
  uint8_t index = 0;
  printf("%sUTXO Outputs:[\n", PRINT_INDENTATION(indentation));
  printf("%s\tOutputs Count: %d\n", PRINT_INDENTATION(indentation), utxo_outputs_count(outputs));

  // print outputs
  if (outputs) {
    LL_FOREACH(outputs, elm) {
      printf("%s\t#%d ", PRINT_INDENTATION(indentation), index);
      switch (elm->output->output_type) {
        case OUTPUT_EXTENDED:
          output_extended_print(elm->output->output, indentation + 1);
          break;
        case OUTPUT_ALIAS:
          output_alias_print(elm->output->output, indentation + 1);
          break;
        case OUTPUT_FOUNDRY:
          output_foundry_print(elm->output->output, indentation + 1);
          break;
        case OUTPUT_NFT:
          output_nft_print(elm->output->output, indentation + 1);
          break;
      }
      index++;
    }
  }

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
