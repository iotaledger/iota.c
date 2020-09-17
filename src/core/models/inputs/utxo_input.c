#include <inttypes.h>
#include <stdio.h>

#include "core/models/inputs/utxo_input.h"

static UT_icd const utxo_inputs_icd = {sizeof(utxo_input_t), NULL, NULL, NULL};

void utxo_input_print(utxo_input_t *utxo) {
  printf("utxo_input id: [");
  for (size_t i = 0; i < TRANSACTION_ID_BYTES; i++) {
    printf("%x,", utxo->tx_id[i]);
  }
  printf("], output index: %" PRIu64 "\n", utxo->output_index);
}

utxo_inputs_t *utxo_inputs_new() {
  utxo_inputs_t *ins = NULL;
  utarray_new(ins, &utxo_inputs_icd);
  return ins;
}

void utxo_inputs_print(utxo_inputs_t *utxo_ins) {
  utxo_input_t *in = NULL;
  UTXO_INPUTS_FOREACH(utxo_ins, in) { utxo_input_print(in); }
}
