#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/address.h"

/**
 * @brief hexadecimal text to a string, ex: "48656c6c6f" -> "Hello"
 *
 * @param str the hex text,
 * @param array output string
 */
void hex_decode_string(char const str[], uint8_t array[]) {
  size_t len = strlen(str) / 2;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') {
      c += (str[i * 2] - '0') << 4;
    }
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F') {
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    }
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
      c += (str[i * 2 + 1] - '0');
    }
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') {
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    }
    array[i] = c;
  }
}

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
