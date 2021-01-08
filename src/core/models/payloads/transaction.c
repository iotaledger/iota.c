// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/payloads/transaction.h"

static int byte_cmp(const byte_t* p1, const byte_t* p2, size_t len) {
  byte_t b1, b2;
  size_t count = 0;
  for (size_t i = 0; i <= len; i++) {
    b1 = p1[i];
    b2 = p2[i];
    if (b1 != b2) {
      return b1 - b2;
    }
  }
  return b1 - b2;
}

static int sort_input_tx_id(utxo_input_ht* a, utxo_input_ht* b) {
  return byte_cmp(a->tx_id, b->tx_id, TRANSACTION_ID_BYTES);
}

static int sort_output_address(sig_unlocked_outputs_ht* a, sig_unlocked_outputs_ht* b) {
  return byte_cmp(a->address, b->address, ED25519_ADDRESS_BYTES);
}

transaction_essence_t* tx_essence_new() {
  transaction_essence_t* es = malloc(sizeof(transaction_essence_t));
  if (es) {
    es->tx_type = 0;  // 0 to denote a transaction essence.
    es->inputs = utxo_inputs_new();
    es->outputs = utxo_outputs_new();
    es->payload = NULL;
    es->payload_len = 0;
  }
  return es;
}

int tx_essence_add_input(transaction_essence_t* es, byte_t tx_id[], uint8_t index) {
  if (es == NULL || tx_id == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  return utxo_inputs_add(&es->inputs, tx_id, index);
}

int tx_essence_add_output(transaction_essence_t* es, byte_t addr[], uint64_t amount) {
  if (es == NULL || addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (amount > MAX_IOTA_SUPPLY) {
    printf("[%s:%d] invalid amount\n", __func__, __LINE__);
    return -1;
  }
  return utxo_outputs_add(&es->outputs, addr, amount);
}

int tx_essence_add_payload(transaction_essence_t* es) {
  // TODO: support transaction with a payload
  return -1;
}

void tx_essence_sort_input_output(transaction_essence_t* es) {
  if (es) {
    HASH_SORT(es->inputs, sort_input_tx_id);
    HASH_SORT(es->outputs, sort_output_address);
  }
}

byte_t* tx_essence_serialize(transaction_essence_t* es, size_t* len) {
  if (!es) {
    return NULL;
  }

  uint8_t input_counts = utxo_inputs_count(&es->inputs);
  uint8_t output_counts = utxo_outputs_count(&es->outputs);
  // at least one input and one output
  if (input_counts == 0) {
    printf("[%s:%d] an input is needed\n", __func__, __LINE__);
    return NULL;
  }

  if (output_counts == 0) {
    printf("[%s:%d] an output is needed\n", __func__, __LINE__);
    return NULL;
  }

  // TODO: transaction with a payload

  // calculating the size of serialized essence with no payload
  size_t essence_bytes = sizeof(uint8_t) + (UTXO_INPUT_SERIALIZED_BYTES * input_counts) +
                         (UTXO_OUTPUT_SERIALIZED_BYTES * output_counts) + sizeof(uint32_t);

  // allocate serialized buffer
  byte_t* serialized = malloc(essence_bytes);
  if (!serialized) {
    printf("[%s:%d] unable to alllocate buffer for serialized essence\n", __func__, __LINE__);
    return NULL;
  }
  memset(serialized, 0, essence_bytes);

  byte_t* offset = serialized;
  // fill-in transaction type, set to value 0 to denote a transaction essence.
  memset(offset, 0, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // Inputs and Ouputs must be in lexicographical order of their serialized form
  tx_essence_sort_input_output(es);

  // serialize inputs
  offset += utxo_inputs_serialization(&es->inputs, offset);

  // serialize outputs
  offset += utxo_outputs_serialization(&es->outputs, offset);

  // TODO: serialize non-empty payload

  *len = essence_bytes;
  return serialized;
}

void tx_essence_free(transaction_essence_t* es) {
  if (es) {
    utxo_inputs_free(&es->inputs);
    utxo_outputs_free(&es->outputs);
    // TODO: payload
    free(es);
  }
}

void tx_essence_print(transaction_essence_t* es) {
  printf("transaction essence:[\n");
  utxo_inputs_print(&es->inputs);
  utxo_outputs_print(&es->outputs);
  printf("\n");
}