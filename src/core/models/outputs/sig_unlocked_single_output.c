// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>

#include "core/models/outputs/sig_unlocked_single_output.h"

#define UTXO_OUTPUT_MIN_COUNT 0
#define UTXO_OUTPUT_MAX_COUNT 126

int utxo_outputs_add(sig_unlocked_outputs_ht **ht, byte_t addr[], uint64_t amount) {
  if (utxo_outputs_count(ht) >= UTXO_OUTPUT_MAX_COUNT) {
    printf("[%s:%d] output count must be < 127\n", __func__, __LINE__);
    return -1;
  }

  sig_unlocked_outputs_ht *elm = utxo_outputs_find_by_addr(ht, addr);
  if (elm) {
    printf("[%s:%d] address exists\n", __func__, __LINE__);
    return -1;
  }

  elm = malloc(sizeof(sig_unlocked_outputs_ht));
  if (elm == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  memcpy(elm->address, addr, ED25519_ADDRESS_BYTES);
  elm->amount = amount;
  HASH_ADD(hh, *ht, address, ED25519_ADDRESS_BYTES, elm);
  return 0;
}

size_t utxo_outputs_serialization(sig_unlocked_outputs_ht **ht, byte_t buf[]) {
  sig_unlocked_outputs_ht *elm, *tmp;
  size_t byte_count = 0;
  uint8_t elm_count = 0;
  HASH_ITER(hh, *ht, elm, tmp) {
    // output type, set to value 0 to denote a SigLockedSingleOutput.
    memset(buf + byte_count, 0, sizeof(byte_t));
    byte_count += sizeof(byte_t);

    // address type, set to value 1 to denote an ed25519.
    memset(buf + byte_count, 1, sizeof(byte_t));
    byte_count += sizeof(byte_t);

    // ed25519 address
    memcpy(buf + byte_count, elm->address, ED25519_ADDRESS_BYTES);
    byte_count += ED25519_ADDRESS_BYTES;

    // amount
    memcpy(buf + byte_count, &elm->amount, sizeof(elm->amount));
    byte_count += sizeof(elm->amount);

    elm_count++;
  }

  if (byte_count != (elm_count * UTXO_OUTPUT_SERIALIZED_BYTES)) {
    printf("[%s:%d] offset error\n", __func__, __LINE__);
    return 0;
  }

  return byte_count;
}

void utxo_outputs_print(sig_unlocked_outputs_ht **ht) {
  sig_unlocked_outputs_ht *elm, *tmp;
  printf("utxo_outputs: [\n");
  HASH_ITER(hh, *ht, elm, tmp) {
    printf("\t[%" PRIu64 "] ", elm->amount);
    dump_hex(elm->address, ED25519_ADDRESS_BYTES);
  }
  printf("]\n");
}