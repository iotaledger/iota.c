// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>

#include "core/models/inputs/utxo_input.h"

#define UTXO_INPUT_MIN_INDEX 0
#define UTXO_INPUT_MAX_INDEX 126

int utxo_inputs_add_with_key(utxo_input_ht **inputs, byte_t const tx_id[], uint16_t index, byte_t const pub[],
                             byte_t const priv[]) {
  if (index > UTXO_INPUT_MAX_INDEX) {
    printf("[%s:%d] invalid index\n", __func__, __LINE__);
    return -1;
  }

  if (utxo_inputs_count(inputs) >= UTXO_INPUT_MAX_INDEX) {
    printf("[%s:%d] inputs count must be < 127\n", __func__, __LINE__);
    return -1;
  }

  utxo_input_ht *elm = utxo_inputs_find_by_id(inputs, tx_id);
  if (elm) {
    printf("[%s:%d] transaction ID exists\n", __func__, __LINE__);
    return -1;
  }

  elm = malloc(sizeof(utxo_input_ht));
  if (elm == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  memcpy(elm->tx_id, tx_id, TRANSACTION_ID_BYTES);
  memcpy(elm->keypair.pub_key, pub, ED_PUBLIC_KEY_BYTES);
  memcpy(elm->keypair.priv, priv, ED_PRIVATE_KEY_BYTES);
  elm->output_index = index;
  HASH_ADD(hh, *inputs, tx_id, TRANSACTION_ID_BYTES, elm);
  return 0;
}

int utxo_inputs_add(utxo_input_ht **inputs, byte_t id[], uint16_t index) {
  if (index > UTXO_INPUT_MAX_INDEX) {
    printf("[%s:%d] invalid index\n", __func__, __LINE__);
    return -1;
  }

  if (utxo_inputs_count(inputs) >= UTXO_INPUT_MAX_INDEX) {
    printf("[%s:%d] inputs count must be < 127\n", __func__, __LINE__);
    return -1;
  }

  utxo_input_ht *elm = utxo_inputs_find_by_id(inputs, id);
  if (elm) {
    printf("[%s:%d] transaction ID exists\n", __func__, __LINE__);
    return -1;
  }

  elm = malloc(sizeof(utxo_input_ht));
  if (elm == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  memcpy(elm->tx_id, id, TRANSACTION_ID_BYTES);
  elm->output_index = index;
  HASH_ADD(hh, *inputs, tx_id, TRANSACTION_ID_BYTES, elm);
  return 0;
}

size_t utxo_inputs_serialization(utxo_input_ht **inputs, byte_t buf[]) {
  utxo_input_ht *elm, *tmp;
  size_t byte_count = 0;
  uint8_t elm_count = 0;
  HASH_ITER(hh, *inputs, elm, tmp) {
    // byte_count += elm_count * UTXO_INPUT_SERIALIZED_BYTES;
    // input type, set to value 0 to denote an UTXO Input.
    memset(buf + byte_count, 0, sizeof(byte_t));
    byte_count += sizeof(byte_t);

    // transaction id
    memcpy(buf + byte_count, elm->tx_id, TRANSACTION_ID_BYTES);
    byte_count += TRANSACTION_ID_BYTES;

    // index
    memcpy(buf + byte_count, &elm->output_index, sizeof(elm->output_index));
    byte_count += sizeof(elm->output_index);

    elm_count++;
  }

  if (byte_count != (elm_count * UTXO_INPUT_SERIALIZED_BYTES)) {
    printf("[%s:%d] offset error\n", __func__, __LINE__);
    return 0;
  }

  return byte_count;
}

void utxo_inputs_print(utxo_input_ht **inputs) {
  utxo_input_ht *elm, *tmp;
  printf("utxo_inputs: [\n");
  HASH_ITER(hh, *inputs, elm, tmp) {
    printf("\t[%d] ", elm->output_index);
    dump_hex(elm->tx_id, TRANSACTION_ID_BYTES);
  }
  printf("]\n");
}
