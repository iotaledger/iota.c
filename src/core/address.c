#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/address.h"

void get_address_from_seed(seed_ctx_t const* const seed, address_version_t version, uint64_t index, byte_t addr_out[]) {
  // TODO
}

// signs the message with privateKey and returns a signature.
void sign_signature(byte_t const seed[], uint64_t index, byte_t const data[], uint64_t data_len, byte_t signature[]) {
  // TODO
}

bool sign_verify_signature(byte_t const seed[], uint64_t index, byte_t signature[], byte_t const data[],
                           size_t data_len) {
  // TODO
  return true;
}
