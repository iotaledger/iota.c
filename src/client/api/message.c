// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/*
#include "client/api/message.h"
#include "client/api/message_tx_outputs.h"

static const UT_icd ut_tx_inputs_icd = {sizeof(payload_tx_input_t), NULL, NULL, NULL};
static const UT_icd ut_tx_outputs_icd = {sizeof(payload_tx_output_t), NULL, NULL, NULL};

static void block_copy(void *_dst, const void *_src) {
  payload_unlock_block_t *dst = (payload_unlock_block_t *)_dst;
  payload_unlock_block_t *src = (payload_unlock_block_t *)_src;
  dst->block_type = src->block_type;
  dst->reference = src->reference;
  dst->sig_block = src->sig_block;
}

static void block_dtor(void *_elt) {
  payload_unlock_block_t *elt = (payload_unlock_block_t *)_elt;
  if (elt->sig_block) {
    free(elt->sig_block);
  }
}

static const UT_icd ut_unlock_blocks_icd = {sizeof(payload_unlock_block_t), NULL, block_copy, block_dtor};

#define UNLOCKED_BLOCKS_MAX_COUNT 126

api_unlock_blocks_t *api_unlock_blocks_new() {
  api_unlock_blocks_t *b;
  utarray_new(b, &ut_unlock_blocks_icd);
  return b;
}

int api_unlock_blocks_add_signature(api_unlock_blocks_t *blocks, char const sig[], size_t sig_len) {
  // TODO need to restrict signature length == (1 + ED_PUBLIC_KEY_BYTES + ED_SIGNATURE_BYTES)?
  if (sig == NULL || blocks == NULL) {
    printf("[%s:%d] NULL parameters\n", __func__, __LINE__);
    return -1;
  }

  payload_unlock_block_t b = {};
  b.block_type = 0;          // 0 denotes a signature block
  b.reference = UINT16_MAX;  // invalid reference index
  b.sig_block = malloc(sig_len);
  if (b.sig_block) {
    memcpy(b.sig_block, sig, sig_len);
    utarray_push_back(blocks, &b);
    return 0;
  }
  printf("[%s:%d] allocate signature block failed\n", __func__, __LINE__);
  return -1;
}

int api_unlock_blocks_add_ref(api_unlock_blocks_t *blocks, uint16_t ref) {
  if (blocks == NULL) {
    printf("[%s:%d] NULL parameters\n", __func__, __LINE__);
    return -1;
  }
  // Unlock Blocks Count must match the amount of inputs. Must be 0 < x < 127.
  if (ref > UNLOCKED_BLOCKS_MAX_COUNT) {
    printf("[%s:%d] reference out of range \n", __func__, __LINE__);
    return -1;
  }

  // TODO, should we check if the reference index points to a valid signature block?

  payload_unlock_block_t b = {};
  b.block_type = 1;  // 1 denotes a reference block
  b.reference = ref;
  b.sig_block = NULL;
  utarray_push_back(blocks, &b);
  return 0;
}

uint16_t api_unlock_blocks_count(api_unlock_blocks_t *blocks) { return utarray_len(blocks); }

char *api_unlock_blocks_get_pub(api_unlock_blocks_t *blocks, uint16_t index) {
  payload_unlock_block_t *b = (payload_unlock_block_t *)utarray_eltptr(blocks, index);
  if (b) {
    if (b->block_type == 0) {
      return b->sig_block + 1;
    }
  }
  return NULL;
}

char *api_unlock_blocks_get_sig(api_unlock_blocks_t *blocks, uint16_t index) {
  payload_unlock_block_t *b = (payload_unlock_block_t *)utarray_eltptr(blocks, index);
  if (b) {
    if (b->block_type == 0) {
      return b->sig_block + (1 + API_PUB_KEY_HEX_STR_LEN);
    }
  }
  return NULL;
}

void api_unlock_blocks_free(api_unlock_blocks_t *blocks) { utarray_free(blocks); }

payload_tx_t *payload_tx_new() {
  payload_tx_t *tx = malloc(sizeof(payload_tx_t));
  if (tx) {
    memset(tx, 0, sizeof(payload_tx_t));
    utarray_new(tx->inputs, &ut_tx_inputs_icd);
    utarray_new(tx->outputs, &ut_tx_outputs_icd);
    tx->unlock_blocks = api_unlock_blocks_new();
    if (!tx->inputs || !tx->outputs || !tx->unlock_blocks) {
      payload_tx_free(tx);
      return NULL;
    }
    return tx;
  }
  return NULL;
}

void payload_tx_free(payload_tx_t *tx) {
  if (tx) {
    if (tx->inputs) {
      utarray_free(tx->inputs);
    }
    if (tx->outputs) {
      utarray_free(tx->outputs);
    }
    if (tx->unlock_blocks) {
      api_unlock_blocks_free(tx->unlock_blocks);
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
    if (msg->parent_msg_ids && (index < api_message_parent_count(msg))) {
      return *(char **)utarray_eltptr(msg->parent_msg_ids, index);
    }
  }
  return NULL;
}

size_t payload_tx_inputs_count(payload_tx_t const *const tx) {
  if (tx) {
    return utarray_len(tx->inputs);
  }
  return 0;
}

char *payload_tx_inputs_tx_id(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_tx_input_t *input = (payload_tx_input_t *)utarray_eltptr(tx->inputs, index);
    if (input) {
      return input->tx_id;
    }
  }
  return NULL;
}

uint32_t payload_tx_inputs_tx_output_index(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_tx_input_t *input = (payload_tx_input_t *)utarray_eltptr(tx->inputs, index);
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

int payload_tx_add_sig_block(payload_tx_t const *const tx, char const sig[], size_t sig_len) {
  if (tx) {
    return api_unlock_blocks_add_signature(tx->unlock_blocks, sig, sig_len);
  }
  return -1;
}

int payload_tx_add_ref_block(payload_tx_t const *const tx, uint16_t ref) {
  if (tx) {
    return api_unlock_blocks_add_ref(tx->unlock_blocks, ref);
  }
  return -1;
}

size_t payload_tx_blocks_count(payload_tx_t const *const tx) {
  if (tx) {
    return api_unlock_blocks_count(tx->unlock_blocks);
  }
  return 0;
}

char *payload_tx_blocks_public_key(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    return api_unlock_blocks_get_pub(tx->unlock_blocks, index);
  }
  return NULL;
}

char *payload_tx_blocks_signature(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    return api_unlock_blocks_get_sig(tx->unlock_blocks, index);
  }
  return NULL;
}

uint16_t payload_tx_blocks_reference(payload_tx_t const *const tx, size_t index) {
  if (tx) {
    payload_unlock_block_t *b = (payload_unlock_block_t *)utarray_eltptr(tx->unlock_blocks, index);
    if (b) {
      if (b->block_type == 1) {
        return b->reference;
      }
    }
  }
  return UINT16_MAX;
}
*/