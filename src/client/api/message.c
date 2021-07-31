// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/message.h"

static const UT_icd ut_tx_intputs_icd = {sizeof(payload_tx_input_t), NULL, NULL, NULL};
static const UT_icd ut_tx_outputs_icd = {sizeof(payload_tx_output_t), NULL, NULL, NULL};
static const UT_icd ut_tx_blocks_icd = {sizeof(payload_unlock_block_t), NULL, NULL, NULL};

payload_tx_t *payload_tx_new() {
  payload_tx_t *tx = (payload_tx_t *)malloc(sizeof(payload_tx_t));
  if (tx) {
    memset(tx, 0, sizeof(payload_tx_t));
    utarray_new(tx->intputs, &ut_tx_intputs_icd);
    utarray_new(tx->outputs, &ut_tx_outputs_icd);
    utarray_new(tx->unlock_blocks, &ut_tx_blocks_icd);
    return tx;
  }
  return NULL;
}

void payload_tx_free(payload_tx_t *tx) {
  if (tx) {
    if (tx->intputs) {
      utarray_free(tx->intputs);
    }
    if (tx->outputs) {
      utarray_free(tx->outputs);
    }
    if (tx->unlock_blocks) {
      utarray_free(tx->unlock_blocks);
    }
    if (tx->payload) {
      if (tx->type == MSG_PAYLOAD_INDEXATION) {
        payload_index_free((payload_index_t *)tx->payload);
      } else {
        // TODO
      }
    }
    free(tx);
  }
}

payload_milestone_t *payload_milestone_new() {
  payload_milestone_t *ms = malloc(sizeof(payload_milestone_t));
  if (ms) {
    utarray_new(ms->signatures, &ut_str_icd);
    ms->index = 0;
    ms->timestamp = 0;
    memset(ms->inclusion_merkle_proof, 0, sizeof(ms->inclusion_merkle_proof));
  }
  return ms;
}

void payload_milestone_free(payload_milestone_t *ms) {
  if (ms) {
    if (ms->signatures) {
      utarray_free(ms->signatures);
    }
    free(ms);
  }
}

payload_index_t *payload_index_new() {
  payload_index_t *idx = malloc(sizeof(payload_index_t));
  if (idx) {
    idx->data = byte_buf_new();
    if (idx->data) {
      idx->index = byte_buf_new();
      if (idx->index) {
        return idx;
      }
      byte_buf_free(idx->data);
      free(idx);
      return NULL;
    }
    free(idx);
    return NULL;
  }
  return NULL;
}

void payload_index_free(payload_index_t *idx) {
  if (idx) {
    byte_buf_free(idx->data);
    byte_buf_free(idx->index);
    free(idx);
  }
}

message_t *api_message_new() {
  message_t *msg = malloc(sizeof(message_t));
  if (msg) {
    memset(msg->net_id, 0, sizeof(msg->net_id));
    utarray_new(msg->parent_msg_ids, &ut_str_icd);
    memset(msg->nonce, 0, sizeof(msg->nonce));
    msg->payload = NULL;
    msg->type = 255;  // invalid payload type
  }
  return msg;
}

void api_message_free(message_t *msg) {
  if (msg) {
    switch (msg->type) {
      case MSG_PAYLOAD_TRANSACTION:
        payload_tx_free((payload_tx_t *)msg->payload);
        break;
      case MSG_PAYLOAD_MILESTONE:
        payload_milestone_free((payload_milestone_t *)msg->payload);
        break;
      case MSG_PAYLOAD_INDEXATION:
        payload_index_free((payload_index_t *)msg->payload);
        break;
      default:
        // do nothing
        break;
    }
    utarray_free(msg->parent_msg_ids);
    free(msg);
  }
}

size_t api_message_parent_count(message_t *msg) {
  if (msg) {
    if (msg->parent_msg_ids) {
      return utarray_len(msg->parent_msg_ids);
    }
  }
  return 0;
}

void api_message_add_parent(message_t *msg, char const *const msg_id) {
  if (msg) {
    utarray_push_back(msg->parent_msg_ids, &msg_id);
  }
}

char *api_message_parent_id(message_t *msg, size_t index) {
  if (msg) {
    if (msg->parent_msg_ids) {
      return *(char **)utarray_eltptr(msg->parent_msg_ids, index);
    }
  }
  return NULL;
}

size_t payload_tx_inputs_count(payload_tx_t const *const tx) {
  if (tx) {
    return utarray_len(tx->intputs);
  }
  return 0;
}

char *payload_tx_inputs_tx_id(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_tx_input_t *input = (payload_tx_input_t *)utarray_eltptr(tx->intputs, index);
    if (input) {
      return input->tx_id;
    }
  }
  return NULL;
}

uint32_t payload_tx_inputs_tx_output_index(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_tx_input_t *input = (payload_tx_input_t *)utarray_eltptr(tx->intputs, index);
    return input->tx_output_index;
  }
  return 0;
}

size_t payload_tx_outputs_count(payload_tx_t const *const tx) {
  if (tx) {
    return utarray_len(tx->outputs);
  }
  return 0;
}

char *payload_tx_outputs_address(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_tx_output_t *out = (payload_tx_output_t *)utarray_eltptr(tx->outputs, index);
    if (out) {
      return out->address;
    }
  }
  return NULL;
}

uint64_t payload_tx_outputs_amount(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_tx_output_t *out = (payload_tx_output_t *)utarray_eltptr(tx->outputs, index);
    if (out) {
      return out->amount;
    }
  }
  return 0;
}

size_t payload_tx_blocks_count(payload_tx_t const *const tx) {
  if (tx) {
    return utarray_len(tx->unlock_blocks);
  }
  return 0;
}

char *payload_tx_blocks_public_key(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_unlock_block_t *b = (payload_unlock_block_t *)utarray_eltptr(tx->unlock_blocks, index);
    if (b) {
      return b->pub_key;
    }
  }
  return NULL;
}

char *payload_tx_blocks_signature(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_unlock_block_t *b = (payload_unlock_block_t *)utarray_eltptr(tx->unlock_blocks, index);
    if (b) {
      return b->signature;
    }
  }
  return NULL;
}
