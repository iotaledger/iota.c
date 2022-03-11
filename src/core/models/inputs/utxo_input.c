// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/outputs.h"

utxo_inputs_list_t *utxo_inputs_new() { return NULL; }

void utxo_inputs_free(utxo_inputs_list_t *inputs) {
  if (inputs) {
    utxo_inputs_list_t *elm, *tmp;
    LL_FOREACH_SAFE(inputs, elm, tmp) {
      if (elm->input->keypair) {
        free(elm->input->keypair);
      }
      free(elm->input);
      LL_DELETE(inputs, elm);
      free(elm);
    }
  }
}

int utxo_inputs_add(utxo_inputs_list_t **inputs, uint8_t type, byte_t id[], uint16_t index, ed25519_keypair_t *key) {
  if (id == NULL) {
    printf("[%s:%d] invalid transaction id\n", __func__, __LINE__);
    return -1;
  }

  // 0<= Transaction Output Index <= max output count
  if (index >= UTXO_OUTPUT_MAX_COUNT) {
    printf("[%s:%d] invalid index\n", __func__, __LINE__);
    return -1;
  }

  // Input Type must denote a UTXO Input.
  if (type != 0) {
    printf("[%s:%d] unknown input type\n", __func__, __LINE__);
    return -1;
  }

  // Transaction ID and Transaction Output Index must be unique
  utxo_input_t *input = utxo_inputs_find_by_id(*inputs, id);
  if (input != NULL) {
    // Check if the duplicate transaction id has the same index,if not we can ignore
    if (input->output_index == index) {
      printf("[%s:%d] Transaction ID and Transaction Output Index must be unique\n", __func__, __LINE__);
      return -1;
    }
  }

  utxo_inputs_list_t *next = malloc(sizeof(utxo_inputs_list_t));
  if (next) {
    next->input = malloc(sizeof(utxo_input_t));
    if (next->input) {
      // Currently only UTXO input is supported
      next->input->input_type = type;
      memcpy(next->input->tx_id, id, IOTA_TRANSACTION_ID_BYTES);
      next->input->output_index = index;
      if (key) {
        next->input->keypair = malloc(sizeof(ed25519_keypair_t));
        if (next->input->keypair) {
          memcpy(next->input->keypair, key, sizeof(ed25519_keypair_t));
          LL_APPEND(*inputs, next);
          return 0;
        }
      } else {
        next->input->keypair = NULL;
        LL_APPEND(*inputs, next);
        return 0;
      }
    }
  }

  if (next) {
    if (next->input) {
      if (next->input->keypair) {
        free(next->input->keypair);
      }
      free(next->input);
    }
    free(next);
  }

  return -1;
}

uint16_t utxo_inputs_count(utxo_inputs_list_t *inputs) {
  utxo_inputs_list_t *elm = NULL;
  uint16_t len = 0;
  if (inputs) {
    LL_COUNT(inputs, elm, len);
  }
  return len;
}

utxo_input_t *utxo_inputs_find_by_id(utxo_inputs_list_t *inputs, byte_t id[]) {
  if (inputs == NULL) {
    printf("[%s:%d] empty input list\n", __func__, __LINE__);
    return NULL;
  }

  if (id == NULL) {
    printf("[%s:%d] invalid transaction id\n", __func__, __LINE__);
    return NULL;
  }

  utxo_inputs_list_t *elm;
  if (inputs) {
    LL_FOREACH(inputs, elm) {
      if (memcmp(elm->input->tx_id, id, IOTA_TRANSACTION_ID_BYTES) == 0) {
        return elm->input;
      }
    }
  }
  return NULL;
}

utxo_input_t *utxo_inputs_find_by_index(utxo_inputs_list_t *inputs, uint16_t index) {
  if (inputs == NULL) {
    printf("[%s:%d] empty input list\n", __func__, __LINE__);
    return NULL;
  }

  if (index >= UTXO_OUTPUT_MAX_COUNT) {
    printf("[%s:%d] invalid index\n", __func__, __LINE__);
    return NULL;
  }

  utxo_inputs_list_t *elm;
  if (inputs) {
    LL_FOREACH(inputs, elm) {
      if (memcmp(&elm->input->output_index, &index, sizeof(uint16_t)) == 0) {
        return elm->input;
      }
    }
  }
  return NULL;
}

size_t utxo_inputs_serialize_len(utxo_inputs_list_t *inputs) {
  if (inputs == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t len = 0;

  // Inputs count
  len += sizeof(uint16_t);

  // Len of a single input
  size_t single_input_len = sizeof(uint8_t) + IOTA_TRANSACTION_ID_BYTES + sizeof(uint16_t);

  len += single_input_len * utxo_inputs_count(inputs);

  return len;
}

size_t utxo_inputs_serialize(utxo_inputs_list_t *inputs, byte_t buf[], size_t buf_len) {
  if (inputs == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid inputs\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = utxo_inputs_serialize_len(inputs);

  if (expected_bytes == 0) {
    printf("[%s:%d] outputs serialized length is zero\n", __func__, __LINE__);
    return 0;
  }

  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  byte_t *offset = buf;

  // number of input entries
  uint16_t input_count = utxo_inputs_count(inputs);
  memcpy(offset, &input_count, sizeof(uint16_t));
  offset += sizeof(uint16_t);

  // inputs
  utxo_inputs_list_t *elm;
  LL_FOREACH(inputs, elm) {
    // input type
    memcpy(offset, &elm->input->input_type, sizeof(uint8_t));
    offset += sizeof(uint8_t);

    // transaction id
    memcpy(offset, elm->input->tx_id, IOTA_TRANSACTION_ID_BYTES);
    offset += IOTA_TRANSACTION_ID_BYTES;

    // output index
    memcpy(offset, &elm->input->output_index, sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  return offset - buf;
}

utxo_inputs_list_t *utxo_inputs_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len < 2) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  utxo_inputs_list_t *inputs = utxo_inputs_new();

  size_t offset = 0;

  // number of input entries
  uint16_t input_count = 0;
  memcpy(&input_count, &buf[offset], sizeof(uint16_t));
  offset += sizeof(uint16_t);

  for (uint16_t i = 0; i < input_count; i++) {
    // create a new output list object
    utxo_inputs_list_t *new_input = malloc(sizeof(utxo_inputs_list_t));
    if (!new_input) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      utxo_inputs_free(inputs);
      return NULL;
    }
    new_input->input = malloc(sizeof(utxo_input_t));
    if (!new_input->input) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      free(new_input);
      utxo_inputs_free(inputs);
      return NULL;
    }
    // keypair is not part of serialization
    new_input->input->keypair = NULL;
    LL_APPEND(inputs, new_input);

    // get input type
    if (buf_len < offset + sizeof(uint8_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      free(new_input);
      utxo_inputs_free(inputs);
      return NULL;
    }
    new_input->input->input_type = buf[offset];
    offset += sizeof(uint8_t);

    // get transaction id
    if (buf_len < offset + IOTA_TRANSACTION_ID_BYTES) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      free(new_input);
      utxo_inputs_free(inputs);
      return NULL;
    }
    memcpy(new_input->input->tx_id, &buf[offset], IOTA_TRANSACTION_ID_BYTES);
    offset += IOTA_TRANSACTION_ID_BYTES;

    // get output index
    if (buf_len < offset + sizeof(uint16_t)) {
      printf("[%s:%d] invalid data length\n", __func__, __LINE__);
      free(new_input);
      utxo_inputs_free(inputs);
      return NULL;
    }
    memcpy(&new_input->input->output_index, &buf[offset], sizeof(uint16_t));
    offset += sizeof(uint16_t);
  }

  return inputs;
}

void utxo_inputs_print(utxo_inputs_list_t *inputs, uint8_t indentation) {
  utxo_inputs_list_t *elm;
  uint8_t index = 0;
  printf("%sUTXO Inputs: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tInputs Count: %d\n", PRINT_INDENTATION(indentation), utxo_inputs_count(inputs));
  if (inputs) {
    LL_FOREACH(inputs, elm) {
      printf("%s\t#%d\n", PRINT_INDENTATION(indentation), index);
      // print input type
      printf("%s\tInput Type: %u\n", PRINT_INDENTATION(indentation), elm->input->input_type);
      // print txn id
      printf("%s\t\tTransaction ID: ", PRINT_INDENTATION(indentation));
      dump_hex_str(elm->input->tx_id, IOTA_TRANSACTION_ID_BYTES);
      // print output index
      printf("%s\t\tOutput Index: %u\n", PRINT_INDENTATION(indentation), elm->input->output_index);
      index++;
    }
  }
  printf("%s]\n", PRINT_INDENTATION(indentation));
}

bool utxo_inputs_syntactic(utxo_inputs_list_t *inputs) {
  // 0 < input count <= max input count
  if (utxo_inputs_count(inputs) < 1 || utxo_inputs_count(inputs) > UTXO_INPUT_MAX_COUNT) {
    printf("[%s:%d] inputs count must > 0 and <= %d\n", __func__, __LINE__, UTXO_INPUT_MAX_COUNT);
    return false;
  }
  return true;
}
