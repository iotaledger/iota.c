// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"

transaction_essence_t* tx_essence_new(uint64_t network_id) {
  transaction_essence_t* es = malloc(sizeof(transaction_essence_t));
  if (es) {
    es->tx_type = TRANSACTION_ESSENCE_TYPE;  // 0 to denote a transaction essence.
    es->network_id = network_id;
    es->inputs = utxo_inputs_new();
    memset(es->inputs_commitment, 0, sizeof(es->inputs_commitment));
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
      tagged_data_free(es->payload);
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
  if (type == CORE_MESSAGE_PAYLOAD_TAGGED) {
    es->payload = tagged_data_clone((tagged_data_payload_t const* const)payload);
    es->payload_len = tagged_data_serialize_len(payload);
  } else {
    return -1;
  }
  return 0;
}

int tx_essence_inputs_commitment_calculate(transaction_essence_t* es, utxo_outputs_list_t* unspent_outputs) {
  if (es == NULL || unspent_outputs == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  void* blake_state = iota_blake2b_new_state();
  if (!blake_state) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  if (iota_blake2b_init(blake_state, sizeof(es->inputs_commitment)) != 0) {
    iota_blake2b_free_state(blake_state);
    return -1;
  }

  byte_t* buf;
  size_t buf_len;
  utxo_outputs_list_t* elm;
  LL_FOREACH(unspent_outputs, elm) {
    switch (elm->output->output_type) {
      case OUTPUT_SINGLE_OUTPUT:
      case OUTPUT_DUST_ALLOWANCE:
      case OUTPUT_TREASURY:
        printf("[%s:%d] deprecated or unsupported output type will not be serialized\n", __func__, __LINE__);
        iota_blake2b_free_state(blake_state);
        return -1;
      case OUTPUT_BASIC: {
        buf_len = output_basic_serialize_len(elm->output->output);
        buf = malloc(buf_len);
        if (!buf) {
          printf("[%s:%d] OOM\n", __func__, __LINE__);
          iota_blake2b_free_state(blake_state);
          return -1;
        }
        if (output_basic_serialize(elm->output->output, buf, buf_len) != buf_len) {
          iota_blake2b_free_state(blake_state);
          free(buf);
          return -1;
        }
        break;
      }
      case OUTPUT_ALIAS: {
        buf_len = output_alias_serialize_len(elm->output->output);
        buf = malloc(buf_len);
        if (!buf) {
          printf("[%s:%d] OOM\n", __func__, __LINE__);
          iota_blake2b_free_state(blake_state);
          return -1;
        }
        if (output_alias_serialize(elm->output->output, buf, buf_len) != buf_len) {
          iota_blake2b_free_state(blake_state);
          free(buf);
          return -1;
        }
        break;
      }
      case OUTPUT_FOUNDRY: {
        buf_len = output_foundry_serialize_len(elm->output->output);
        buf = malloc(buf_len);
        if (!buf) {
          printf("[%s:%d] OOM\n", __func__, __LINE__);
          iota_blake2b_free_state(blake_state);
          return -1;
        }
        if (output_foundry_serialize(elm->output->output, buf, buf_len) != buf_len) {
          iota_blake2b_free_state(blake_state);
          free(buf);
          return -1;
        }
        break;
      }
      case OUTPUT_NFT: {
        buf_len = output_nft_serialize_len(elm->output->output);
        buf = malloc(buf_len);
        if (!buf) {
          printf("[%s:%d] OOM\n", __func__, __LINE__);
          iota_blake2b_free_state(blake_state);
          return -1;
        }
        if (output_nft_serialize(elm->output->output, buf, buf_len) != buf_len) {
          iota_blake2b_free_state(blake_state);
          free(buf);
          return -1;
        }
        break;
      }
    }
    if (iota_blake2b_update(blake_state, buf, buf_len) != 0) {
      iota_blake2b_free_state(blake_state);
      free(buf);
      return -1;
    }
    free(buf);
  }

  if (iota_blake2b_final(blake_state, es->inputs_commitment, sizeof(es->inputs_commitment)) != 0) {
    iota_blake2b_free_state(blake_state);
    return -1;
  }

  iota_blake2b_free_state(blake_state);

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
  // network Id(uint64_t)
  length += sizeof(uint64_t);
  // input serialized len, this includes input count len
  length += utxo_inputs_serialize_len(es->inputs);
  // inputs commitment
  length += sizeof(es->inputs_commitment);
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

  // serialize network Id
  memcpy(offset, &es->network_id, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // serialize inputs
  size_t input_ser_len = utxo_inputs_serialize_len(es->inputs);
  offset += utxo_inputs_serialize(es->inputs, offset, input_ser_len);

  // serialize inputs commitment
  memcpy(offset, &es->inputs_commitment, CRYPTO_BLAKE2B_256_HASH_BYTES);
  offset += CRYPTO_BLAKE2B_256_HASH_BYTES;

  // serialize outputs
  size_t output_ser_len = utxo_outputs_serialize_len(es->outputs);
  offset += utxo_outputs_serialize(es->outputs, offset, output_ser_len);

  if (es->payload) {
    // serialize tagged data payload
    memcpy(offset, &es->payload_len, sizeof(es->payload_len));
    offset += sizeof(es->payload_len);
    size_t tagged_data_ser_len = tagged_data_serialize_len((tagged_data_payload_t*)es->payload);
    offset += tagged_data_serialize((tagged_data_payload_t*)es->payload, offset, tagged_data_ser_len);
  } else {
    memset(offset, 0, sizeof(uint32_t));
    offset += sizeof(uint32_t);
  }

  return offset - buf;
}

transaction_essence_t* tx_essence_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len < 2) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  transaction_essence_t* es = tx_essence_new(0);

  size_t offset = 0;

  // transaction type
  memcpy(&es->tx_type, &buf[offset], sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // network Id
  memcpy(&es->network_id, &buf[offset], sizeof(uint64_t));
  offset += sizeof(uint64_t);

  // inputs
  es->inputs = utxo_inputs_deserialize(&buf[offset], buf_len - offset);
  if (es->inputs == NULL) {
    tx_essence_free(es);
    return NULL;
  }
  offset += utxo_inputs_serialize_len(es->inputs);

  // inputs commitment
  memcpy(&es->inputs_commitment, &buf[offset], CRYPTO_BLAKE2B_256_HASH_BYTES);
  offset += CRYPTO_BLAKE2B_256_HASH_BYTES;

  // outputs
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
    es->payload = tagged_data_deserialize(&buf[offset], buf_len - offset);
    if (es->outputs == NULL) {
      tx_essence_free(es);
      return NULL;
    }
  }

  return es;
}

bool tx_essence_syntactic(transaction_essence_t* es, byte_cost_config_t* byte_cost) {
  // inputs
  if (!utxo_inputs_syntactic(es->inputs)) {
    return false;
  }

  // outputs
  if (!utxo_outputs_syntactic(es->outputs, byte_cost)) {
    return false;
  }

  return true;
}

void tx_essence_print(transaction_essence_t* es, uint8_t indentation) {
  printf("%sTransaction Essence: [\n", PRINT_INDENTATION(indentation));
  printf("%s\tType: %d\n", PRINT_INDENTATION(indentation), es->tx_type);
  printf("%s\tNetwork Id: %" PRIu64 "\n", PRINT_INDENTATION(indentation), es->network_id);

  utxo_inputs_print(es->inputs, indentation + 1);
  printf("%s\tInputs Commitment: ", PRINT_INDENTATION(indentation));
  dump_hex_str(es->inputs_commitment, sizeof(es->inputs_commitment));
  utxo_outputs_print(es->outputs, indentation + 1);

  if (es->payload_len > 0) {
    tagged_data_print((tagged_data_payload_t*)(es->payload), indentation + 1);
  }

  printf("%s]\n", PRINT_INDENTATION(indentation));
}

transaction_payload_t* tx_payload_new(uint64_t network_id) {
  transaction_payload_t* tx = malloc(sizeof(transaction_payload_t));
  if (tx) {
    tx->type = CORE_MESSAGE_PAYLOAD_TRANSACTION;  // 0 to denote a Transaction payload.
    tx->essence = tx_essence_new(network_id);
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

size_t tx_payload_serialize_length(transaction_payload_t* tx) {
  size_t essence_len = tx_essence_serialize_length(tx->essence);
  size_t blocks_len = unlock_blocks_serialize_length(tx->unlock_blocks);
  if (essence_len == 0 || blocks_len == 0) {
    return 0;
  }

  // payload_type + serialized essence length + serialized unlocked blocks
  return sizeof(uint32_t) + essence_len + blocks_len;
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
  memset(offset, CORE_MESSAGE_PAYLOAD_TRANSACTION, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  // write essence
  size_t essence_len = tx_essence_serialize_length(tx->essence);
  offset += tx_essence_serialize(tx->essence, offset, essence_len);
  // write unlocked blocks
  offset += unlock_blocks_serialize(tx->unlock_blocks, offset);

  return offset - buf;
}

transaction_payload_t* tx_payload_deserialize(byte_t buf[], size_t buf_len) {
  if (buf == NULL || buf_len < 2) {
    printf("[%s:%d] invalid paramters\n", __func__, __LINE__);
    return NULL;
  }

  transaction_payload_t* tx_payload = malloc(sizeof(transaction_payload_t));
  if (!tx_payload) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  size_t offset = 0;

  // transaction payload type
  memcpy(&tx_payload->type, &buf[offset], sizeof(uint32_t));
  offset += sizeof(uint32_t);

  tx_payload->essence = tx_essence_deserialize(&buf[offset], buf_len - offset);
  offset += tx_essence_serialize_length(tx_payload->essence);

  tx_payload->unlock_blocks = unlock_blocks_deserialize(&buf[offset], buf_len - offset);
  offset += unlock_blocks_serialize_length(tx_payload->unlock_blocks);

  return tx_payload;
}

void tx_payload_print(transaction_payload_t* tx, uint8_t indentation) {
  if (tx) {
    tx_essence_print(tx->essence, indentation);
    unlock_blocks_print(tx->unlock_blocks, indentation);
  }
}

bool tx_payload_syntactic(transaction_payload_t* tx, byte_cost_config_t* byte_cost) {
  if (!tx) {
    return false;
  }

  // essence
  if (!tx_essence_syntactic(tx->essence, byte_cost)) {
    return false;
  }

  // Unlock Block Count must match Input Count
  if (utxo_inputs_count(tx->essence->inputs) != unlock_blocks_count(tx->unlock_blocks)) {
    return false;
  }

  return true;
}
