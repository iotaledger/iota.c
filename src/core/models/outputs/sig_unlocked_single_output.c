#include <inttypes.h>
#include <stdio.h>

#include "core/models/outputs/sig_unlocked_single_output.h"

static UT_icd const suso_icd = {sizeof(sig_unlocked_single_output_t), NULL, NULL, NULL};

void output_suso_print(sig_unlocked_single_output_t *output) {
  printf("output addr: [");
  for (size_t i = 0; i < ED25519_ADDRESS_BYTES; i++) {
    printf("%d,", output->addr[i]);
  }
  printf("], amount: %" PRIu64 "\n", output->amount);
}

output_suso_array_t *outputs_suso_new() {
  output_suso_array_t *outs = NULL;
  utarray_new(outs, &suso_icd);
  return outs;
}

void outputs_suso_array_print(output_suso_array_t *outs) {
  sig_unlocked_single_output_t *elm = NULL;
  OUTPUTS_SUSO_FOREACH(outs, elm) { output_suso_print(elm); }
}
