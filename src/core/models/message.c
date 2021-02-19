// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"

#include "core/models/message.h"

static const UT_icd ut_msg_id_icd = {sizeof(uint8_t) * IOTA_MESSAGE_ID_BYTES, NULL, NULL, NULL};

typedef struct {
  byte_t pub_key[ED_PUBLIC_KEY_BYTES];  // The public key of the Ed25519 keypair which is used to verify the signature.
  byte_t signature[ED_SIGNATURE_BYTES];
  uint16_t unlock_index;
  UT_hash_handle hh;
} unlock_sig_ht;

static unlock_sig_ht* unlock_sig_new() { return NULL; }

static uint16_t unlock_sig_count(unlock_sig_ht** ht) { return (uint16_t)HASH_COUNT(*ht); }

static unlock_sig_ht* unlock_sig_find_by_pub(unlock_sig_ht** ht, byte_t pub[]) {
  unlock_sig_ht* in = NULL;
  HASH_FIND(hh, *ht, pub, ED_PUBLIC_KEY_BYTES, in);
  return in;
}

static int unlock_sig_add(unlock_sig_ht** ht, ed25519_signature_t* sig, uint16_t index) {
  unlock_sig_ht* elm = unlock_sig_find_by_pub(ht, sig->pub_key);
  if (elm) {
    printf("[%s:%d] public key exists\n", __func__, __LINE__);
    return -1;
  }

  elm = malloc(sizeof(unlock_sig_ht));
  if (elm == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }
  memcpy(elm->pub_key, sig->pub_key, ED_PUBLIC_KEY_BYTES);
  memcpy(elm->signature, sig->signature, ED_SIGNATURE_BYTES);
  elm->unlock_index = index;
  HASH_ADD(hh, *ht, pub_key, ED_PUBLIC_KEY_BYTES, elm);
  return 0;
}

static void unlock_sig_free(unlock_sig_ht** ht) {
  unlock_sig_ht *curr_elm, *tmp;
  HASH_ITER(hh, *ht, curr_elm, tmp) {
    HASH_DEL(*ht, curr_elm);
    free(curr_elm);
  }
}

core_message_t* core_message_new() {
  core_message_t* msg = malloc(sizeof(core_message_t));
  if (msg) {
    msg->network_id = 0;
    utarray_new(msg->parents, &ut_msg_id_icd);
    msg->payload_type = UINT32_MAX - 1;  // invalid payload type
    msg->payload = NULL;
    msg->nonce = 0;
  }
  return msg;
}

int core_message_sign_transaction(core_message_t* msg) {
  int ret = -1;
  byte_t essence_hash[CRYPTO_BLAKE2B_HASH_BYTES] = {};
  if (!msg) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (msg->payload_type != 0 || msg->payload == NULL) {
    printf("[%s:%d] invalid payload\n", __func__, __LINE__);
    return -1;
  }

  transaction_payload_t* tx = (transaction_payload_t*)msg->payload;
  // serialize transaction essence
  size_t essence_len = tx_essence_serialize_length(tx->essence);
  byte_t* b_essence = malloc(essence_len);
  if (!b_essence) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  size_t serialized_size = tx_essence_serialize(tx->essence, b_essence);
  if (serialized_size != essence_len) {
    printf("[%s:%d] serialize length miss match\n", __func__, __LINE__);
    free(b_essence);
    return -1;
  }

  // essence hash
  if (iota_blake2b_sum(b_essence, serialized_size, essence_hash, sizeof(essence_hash)) != 0) {
    printf("[%s:%d] get essence hash failed\n", __func__, __LINE__);
    free(b_essence);
    return -1;
  }

  unlock_sig_ht* unlocked_sig = unlock_sig_new();
  // create unlocked blocks and sign tx essence
  utxo_input_ht *elm, *tmp;
  HASH_ITER(hh, tx->essence->inputs, elm, tmp) {
    // create a ref block, if public key exists in unlocked_sig
    if (unlock_sig_find_by_pub(&unlocked_sig, elm->keypair.pub_key)) {
      // create a reference block
      if ((ret = tx_blocks_add_reference(&tx->unlock_blocks, unlock_sig_count(&unlocked_sig) - 1))) {
        break;
      }
    } else {
      // sign transaction
      ed25519_signature_t signature = {};
      signature.type = ADDRESS_VER_ED25519;
      if ((ret = iota_crypto_sign(elm->keypair.priv, essence_hash, CRYPTO_BLAKE2B_HASH_BYTES, signature.signature))) {
        break;
      }
      memcpy(signature.pub_key, elm->keypair.pub_key, ED_PUBLIC_KEY_BYTES);

      // create a signature block
      if ((ret = tx_blocks_add_signature(&tx->unlock_blocks, &signature))) {
        break;
      }

      // add to unlocked sig
      if ((ret = unlock_sig_add(&unlocked_sig, &signature, unlock_sig_count(&unlocked_sig)))) {
        break;
      }
    }
  }

  if (unlocked_sig) {
    unlock_sig_free(&unlocked_sig);
  }
  if (b_essence) {
    free(b_essence);
  }
  return ret;
}

void core_message_free(core_message_t* msg) {
  if (msg) {
    if (msg->payload) {
      if (msg->payload_type == 0) {
        tx_payload_free((transaction_payload_t*)msg->payload);
      }
      if (msg->payload_type == 2) {
        indexation_free((indexation_t*)msg->payload);
      }
      // TODO support other payload
    }
    utarray_free(msg->parents);
    free(msg);
  }
}

void core_message_add_parent(core_message_t* msg, byte_t const msg_id[]) {
  if (msg) {
    utarray_push_back(msg->parents, msg_id);
  }
}

size_t core_message_parent_len(core_message_t* msg) {
  if (msg) {
    return utarray_len(msg->parents);
  }
  return 0;
}