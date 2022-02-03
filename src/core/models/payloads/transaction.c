// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/models/message.h"
#include "core/models/payloads/transaction.h"
#include "utlist.h"

transaction_essence_t* tx_essence_new() {
  transaction_essence_t* es = malloc(sizeof(transaction_essence_t));
  if (es) {
    es->tx_type = CORE_MESSAGE_PAYLOAD_TRANSACTION;  // 0 to denote a transaction essence.
    es->inputs = utxo_inputs_new();
    es->outputs = utxo_outputs_new();
    es->payload = NULL;
    es->payload_len = 0;
  }
  return es;
}

void tx_essence_free(transaction_essence_t* es) {
  if (es) {
    utxo_inputs_free(es->inputs);
    utxo_outputs_free(es->outputs);

    if (es->payload) {
      // TODO: support other payloads
      indexation_free(es->payload);
    }
    free(es);
  }
}

int tx_essence_add_input(transaction_essence_t* es, uint8_t type, byte_t tx_id[], uint8_t index) {
  if (es == NULL || tx_id == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  return utxo_inputs_add(&es->inputs, type, tx_id, index);
}

int tx_essence_add_output(transaction_essence_t* es, utxo_output_type_t type, void* output) {
  if (es == NULL || output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  return utxo_outputs_add(&es->outputs, type, output);
}

int tx_essence_add_payload(transaction_essence_t* es, uint32_t type, void* payload) {
  if (!es || !payload) {
    return -1;
  }
  // TODO: support indexation payload at this moment
  if (type == CORE_MESSAGE_PAYLOAD_INDEXATION) {
    es->payload = payload;
    es->payload_len = indexation_serialize_length(payload);
  } else {
    return -1;
  }
  return 0;
}

size_t tx_essence_serialize_length(transaction_essence_t* es) {
  size_t length = 0;
  uint16_t input_count = utxo_inputs_count(es->inputs);
  uint16_t output_count = utxo_outputs_count(es->outputs);
  // at least one input and one output
  if (input_count == 0) {
    printf("[%s:%d] an input is needed\n", __func__, __LINE__);
    return 0;
  }

  if (output_count == 0) {
    printf("[%s:%d] an output is needed\n", __func__, __LINE__);
    return 0;
  }

  // transaction type(uint8_t)
  length += sizeof(uint8_t);
  // input serialized len, this includes input count len
  length += utxo_inputs_serialize_len(es->inputs);
  // output serialized len, this includes output count len
  length += utxo_outputs_serialize_len(es->outputs);

  // payload length (uint32_t) + serialized payload
  length += sizeof(uint32_t);
  if (es->payload) {
    length += es->payload_len;
  }
  return length;
}

size_t tx_essence_serialize(transaction_essence_t* es, byte_t buf[], size_t buf_len) {
  if (!es) {
    printf("[%s:%d] NULL parameter\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = tx_essence_serialize_length(es);

  if (expected_bytes == 0) {
    printf("[%s:%d] essence serialized length is zero\n", __func__, __LINE__);
    return 0;
  }

  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  byte_t* offset = buf;
  // fill-in essence type, set to value 0 to denote a transaction essence.
  memcpy(offset, &es->tx_type, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // serialize inputs
  size_t input_ser_len = utxo_inputs_serialize_len(es->inputs);
  offset += utxo_inputs_serialize(es->inputs, offset, input_ser_len);

  // serialize outputs
  size_t output_ser_len = utxo_outputs_serialize_len(es->outputs);
  offset += utxo_outputs_serialize(es->outputs, offset, output_ser_len);

  if (es->payload) {
    // serialize indexation payload
    memcpy(offset, &es->payload_len, sizeof(es->payload_len));
    offset += sizeof(es->payload_len);
    offset += indexation_payload_serialize((indexation_t*)es->payload, offset);
  } else {
    memset(offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
  }
  return expected_bytes;
}

transaction_essence_t* tx_essence_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len < 2) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  transaction_essence_t* es = tx_essence_new();

  size_t offset = 0;

  // transaction type
  memcpy(&es->tx_type, &buf[offset], sizeof(uint8_t));
  offset += sizeof(uint8_t);

  es->inputs = utxo_inputs_deserialize(&buf[offset], buf_len - offset);
  if (es->inputs == NULL) {
    tx_essence_free(es);
    return NULL;
  }
  offset += utxo_inputs_serialize_len(es->inputs);

  es->outputs = utxo_outputs_deserialize(&buf[offset], buf_len - offset);
  if (es->outputs == NULL) {
    tx_essence_free(es);
    return NULL;
  }
  offset += utxo_outputs_serialize_len(es->outputs);

  // transaction type
  if (buf_len < offset + sizeof(uint32_t)) {
    printf("[%s:%d] invalid data length\n", __func__, __LINE__);
    tx_essence_free(es);
    return NULL;
  }
  memcpy(&es->payload_len, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  if (es->payload_len > 0) {
    // TODO: Deserialize indexation payload
  }

  return es;
}

void tx_essence_print(transaction_essence_t* es) {
  printf("Transaction Essence: [\n");
  utxo_inputs_print(es->inputs, 1);
  utxo_outputs_print(es->outputs, 1);
  // TODO: print payloads
  printf("]\n");
}

transaction_payload_t* tx_payload_new() {
  transaction_payload_t* tx = malloc(sizeof(transaction_payload_t));
  if (tx) {
    tx->type = CORE_MESSAGE_PAYLOAD_TRANSACTION;  // 0 to denote a Transaction payload.
    tx->essence = tx_essence_new();
    tx->unlock_blocks = unlock_blocks_new();
    if (tx->essence == NULL) {
      tx_payload_free(tx);
      return NULL;
    }
  }
  return tx;
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

int tx_payload_add_input(transaction_payload_t* tx, uint8_t type, byte_t tx_id[], uint8_t index) {
  if (tx) {
    return tx_essence_add_input(tx->essence, type, tx_id, index);
  }
  return -1;
}

int tx_payload_add_output(transaction_payload_t* tx, utxo_output_type_t type, void* output) {
  if (tx) {
    return tx_essence_add_output(tx->essence, type, output);
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

size_t tx_payload_serialize(transaction_payload_t* tx, byte_t buf[], size_t buf_len) {
  if (tx == NULL) {
    return -1;
  }

  size_t expected_bytes = tx_payload_serialize_length(tx);

  if (expected_bytes == 0) {
    printf("[%s:%d] transaction payload serialized length is zero\n", __func__, __LINE__);
    return 0;
  }

  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  byte_t* offset = buf;
  // write payload type
  memset(offset, CORE_MESSAGE_PAYLOAD_TRANSACTION, sizeof(payload_t));
  offset += sizeof(payload_t);
  // write essence
  size_t essence_len = tx_essence_serialize_length(tx->essence);
  offset += tx_essence_serialize(tx->essence, offset, essence_len);
  // write unlocked blocks
  offset += unlock_blocks_serialize(tx->unlock_blocks, offset);

  return expected_bytes;
}

transaction_payload_t* tx_payload_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len < 2) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  transaction_payload_t* tx_payload = tx_payload_new();

  size_t offset = 0;

  // transaction payload type
  memcpy(&tx_payload->type, &buf[offset], sizeof(payload_t));
  offset += sizeof(payload_t);

  tx_payload->essence = tx_essence_deserialize(&buf[offset], buf_len - offset);
  offset += tx_essence_serialize_length(tx_payload->essence);

  // TODO: Unlock Block Deserialize

  return tx_payload;
}

void tx_payload_print(transaction_payload_t* tx) {
  if (tx) {
    printf("Payload type: %d\n", tx->type);
    tx_essence_print(tx->essence);
    unlock_blocks_print(tx->unlock_blocks);
  }
}
