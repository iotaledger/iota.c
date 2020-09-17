#include <inttypes.h>
#include <stdio.h>

#include "core/models/outputs/sig_unlocked_single_deposit.h"

static UT_icd const susd_icd = {sizeof(sig_unlocked_single_deposit_t), NULL, NULL, NULL};

void output_susd_print(sig_unlocked_single_deposit_t *output) {
  printf("output addr: [");
  for (size_t i = 0; i < IOTA_ADDRESS_BYTES; i++) {
    printf("%d,", output->addr[i]);
  }
  printf("], amount: %" PRIu64 "\n", output->amount);
}

output_susd_array_t *outputs_susd_new() {
  output_susd_array_t *outs = NULL;
  utarray_new(outs, &susd_icd);
  return outs;
}

void outputs_susd_array_print(output_susd_array_t *outs) {
  sig_unlocked_single_deposit_t *elm = NULL;
  OUTPUTS_SUSD_FOREACH(outs, elm) { output_susd_print(elm); }
}
