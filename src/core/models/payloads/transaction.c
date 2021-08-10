// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "utlist.h"

#include "core/models/payloads/transaction.h"

#define UNLOCKED_BLOCKS_MAX_COUNT 126

// unlock_block_t + reference = 1 + 2
#define REFERENCE_SERIALIZE_BYTES (1 + sizeof(uint16_t))
//  unlock_block_t + signature type + pub_key + signature
#define SIGNATURE_SERIALIZE_BYTES (1 + (1 + ED_PUBLIC_KEY_BYTES + ED_SIGNATURE_BYTES))

static int byte_cmp(const byte_t* p1, const byte_t* p2, size_t len) {
  byte_t b1 = 0, b2 = 0;
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

static int sort_output_address(outputs_ht* a, outputs_ht* b) {
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

int tx_essence_add_input_with_key(transaction_essence_t* es, byte_t const tx_id[], uint8_t index, byte_t const pub[],
                                  byte_t const priv[]) {
  if (!es || !tx_id || !pub || !priv) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  return utxo_inputs_add_with_key(&es->inputs, tx_id, index, pub, priv);
}

int tx_essence_add_output(transaction_essence_t* es, output_type_t type, byte_t addr[], uint64_t amount) {
  if (es == NULL || addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (amount > MAX_IOTA_SUPPLY) {
    printf("[%s:%d] invalid amount\n", __func__, __LINE__);
    return -1;
  }
  return utxo_outputs_add(&es->outputs, type, addr, amount);
}

void tx_essence_sort_input_output(transaction_essence_t* es) {
  if (es) {
    HASH_SORT(es->inputs, sort_input_tx_id);
    HASH_SORT(es->outputs, sort_output_address);
  }
}

int tx_essence_add_payload(transaction_essence_t* es, uint32_t type, void* payload) {
  if (!es || !payload) {
    return -1;
  }
  // TODO: support indexation payload at this moment
  if (type == 2) {
    es->payload = payload;
    es->payload_len = indexaction_serialize_length(payload);
  } else {
    return -1;
  }
  return 0;
}

size_t tx_essence_serialize_length(transaction_essence_t* es) {
  size_t length = 0;
  uint8_t input_counts = utxo_inputs_count(&es->inputs);
  uint8_t output_counts = utxo_outputs_count(&es->outputs);
  // at least one input and one output
  if (input_counts == 0) {
    printf("[%s:%d] an input is needed\n", __func__, __LINE__);
    return 0;
  }

  if (output_counts == 0) {
    printf("[%s:%d] an output is needed\n", __func__, __LINE__);
    return 0;
  }

  // transaction type(uint8_t)
  length += sizeof(uint8_t);
  // input count (uint16_t) + serialized input
  length += sizeof(uint16_t) + (UTXO_INPUT_SERIALIZED_BYTES * input_counts);
  // output count(uint16_t) + serialized output
  length += sizeof(uint16_t) + (UTXO_OUTPUT_SERIALIZED_BYTES * output_counts);

  // payload length (uint32_t) + serialized payload
  length += sizeof(uint32_t);
  if (es->payload) {
    length += es->payload_len;
  }
  return length;
}

size_t tx_essence_serialize(transaction_essence_t* es, byte_t buf[]) {
  if (!es) {
    printf("[%s:%d] NULL parameter\n", __func__, __LINE__);
    return 0;
  }
  uint16_t input_counts = utxo_inputs_count(&es->inputs);
  uint16_t output_counts = utxo_outputs_count(&es->outputs);

  byte_t* offset = buf;
  // fill-in essence type, set to value 0 to denote a transaction essence.
  memset(offset, 0, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // Inputs and Outputs must be in lexicographical order of their serialized form
  tx_essence_sort_input_output(es);

  // input counts
  memcpy(offset, &input_counts, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  // serialize inputs
  offset += utxo_inputs_serialization(&es->inputs, offset);

  // output counts
  memcpy(offset, &output_counts, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  // serialize outputs
  offset += utxo_outputs_serialization(&es->outputs, offset);

  if (es->payload) {
    // serialize indexation payload
    memcpy(offset, &es->payload_len, sizeof(es->payload_len));
    offset += sizeof(es->payload_len);
    offset += indexation_payload_serialize((indexation_t*)es->payload, offset);
  } else {
    memset(offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
  }
  return (offset - buf) / sizeof(byte_t);
}

void tx_essence_free(transaction_essence_t* es) {
  if (es) {
    utxo_inputs_free(&es->inputs);
    utxo_outputs_free(&es->outputs);

    if (es->payload) {
      // TODO support other payloads
      indexation_free(es->payload);
    }
    free(es);
  }
}

void tx_essence_print(transaction_essence_t* es) {
  printf("transaction essence:[\n");
  utxo_inputs_print(&es->inputs);
  utxo_outputs_print(&es->outputs);
  printf("]\n");
}

transaction_payload_t* tx_payload_new() {
  transaction_payload_t* tx = malloc(sizeof(transaction_payload_t));
  if (tx) {
    tx->type = 0;  // 0 to denote a Transaction payload.
    tx->essence = tx_essence_new();
    tx->unlock_blocks = unlock_blocks_new();
    if (tx->essence == NULL) {
      tx_payload_free(tx);
      return NULL;
    }
  }
  return tx;
}

int tx_payload_add_input(transaction_payload_t* tx, byte_t tx_id[], uint8_t index) {
  if (tx) {
    return tx_essence_add_input(tx->essence, tx_id, index);
  }
  return -1;
}

int tx_payload_add_input_with_key(transaction_payload_t* tx, byte_t tx_id[], uint8_t index, byte_t const pub[],
                                  byte_t const priv[]) {
  if (tx) {
    return tx_essence_add_input_with_key(tx->essence, tx_id, index, pub, priv);
  }
  return -1;
}

int tx_payload_add_output(transaction_payload_t* tx, output_type_t type, byte_t addr[], uint64_t amount) {
  if (tx) {
    return tx_essence_add_output(tx->essence, type, addr, amount);
  }
  return -1;
}

int tx_payload_add_sig_block(transaction_payload_t* tx, byte_t* sig_block, size_t sig_len) {
  if (tx) {
    return unlock_blocks_add_signature(&tx->unlock_blocks, sig_block, sig_len);
  }
  return -1;
}

int tx_payload_add_ref_block(transaction_payload_t* tx, uint16_t ref) {
  if (tx) {
    return unlock_blocks_add_reference(&tx->unlock_blocks, ref);
  }
  return -1;
}

size_t tx_payload_serialize_length(transaction_payload_t* tx) {
  size_t essence_len = tx_essence_serialize_length(tx->essence);
  size_t blocks_len = unlock_blocks_serialize_length(tx->unlock_blocks);
  if (essence_len == 0 || blocks_len == 0) {
    return 0;
  }

  // payload_type + serialized essence length + serialized unlocked blocks
  return sizeof(payload_t) + essence_len + blocks_len;
}

size_t tx_payload_serialize(transaction_payload_t* tx, byte_t buf[]) {
  if (tx == NULL) {
    return -1;
  }

  byte_t* offset = buf;
  // write payload type
  memset(offset, 0, sizeof(payload_t));
  offset += sizeof(payload_t);
  // write essence
  offset += tx_essence_serialize(tx->essence, offset);
  // write unlocked blocks
  offset += unlock_blocks_serialize(tx->unlock_blocks, offset);
  return (offset - buf) / sizeof(byte_t);
}

void tx_payload_free(transaction_payload_t* tx) {
  if (tx) {
    if (tx->essence) {
      tx_essence_free(tx->essence);
    }
    if (tx->unlock_blocks) {
      unlock_blocks_free(tx->unlock_blocks);
    }
    free(tx);
  }
}

void tx_payload_print(transaction_payload_t* tx) {
  if (tx) {
    printf("Payload type: %d\n", tx->type);
    tx_essence_print(tx->essence);
    unlock_blocks_print(tx->unlock_blocks);
  }
}
