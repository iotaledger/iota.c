#include <inttypes.h>
#include <stdio.h>

#include "core/models/inputs/utxo_input.h"

#define UTXO_INPUT_MIN_INDEX 0
#define UTXO_INPUT_MAX_INDEX 126

int utxo_inputs_add(utxo_input_ht **inputs, byte_t id[], uint8_t index) {
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

void utxo_inputs_print(utxo_input_ht **inputs) {
  utxo_input_ht *elm, *tmp;
  printf("utxo_inputs: [\n");
  HASH_ITER(hh, *inputs, elm, tmp) {
    printf("[%d] ", elm->output_index);
    dump_hex(elm->tx_id, TRANSACTION_ID_BYTES);
  }
  printf("]\n");
}
