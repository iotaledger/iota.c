// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"

#include "core/models/message.h"
#include "core/models/payloads/transaction.h"
#include "crypto/iota_crypto.h"

static const UT_icd ut_msg_id_icd = {sizeof(uint8_t) * IOTA_MESSAGE_ID_BYTES, NULL, NULL, NULL};

core_message_t* core_message_new() {
  core_message_t* msg = malloc(sizeof(core_message_t));
  if (msg) {
    msg->network_id = 0;
    utarray_new(msg->parents, &ut_str_icd);
    msg->payload_type = CORE_MESSAGE_PAYLOAD_UNKNOWN;  // invalid payload type
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

  if (msg->payload_type != CORE_MESSAGE_PAYLOAD_TRANSACTION || msg->payload == NULL) {
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

  size_t serialized_size = tx_essence_serialize(tx->essence, b_essence, essence_len);
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

  // FIXME, create unlocked blocks and sign tx essence
#if 0
  utxo_input_ht *elm, *tmp;
  HASH_ITER(hh, tx->essence->inputs, elm, tmp) {
    // create a ref block, if public key exists in unlocked_sig
    uint32_t pub_index = unlock_blocks_find_pub(tx->unlock_blocks, elm->keypair.pub);
    if (pub_index == -1) {
      // publick key is not found in the unlocked block
      byte_t sig_block[ED25519_SIGNATURE_BLOCK_BYTES] = {};
      sig_block[0] = ADDRESS_TYPE_ED25519;
      memcpy(sig_block + 1, elm->keypair.pub, ED_PUBLIC_KEY_BYTES);
      // sign transaction
      if ((ret = iota_crypto_sign(elm->keypair.priv, essence_hash, CRYPTO_BLAKE2B_HASH_BYTES,
                                  sig_block + (1 + ED_PUBLIC_KEY_BYTES)))) {
        printf("[%s:%d] signing signature failed\n", __func__, __LINE__);
        break;
      }

      // create a signature block
      if ((ret = unlock_blocks_add_signature(&tx->unlock_blocks, sig_block, ED25519_SIGNATURE_BLOCK_BYTES))) {
        printf("[%s:%d] Add signature block failed\n", __func__, __LINE__);
        break;
      }
    } else {
      // public key is found in the unlocked block
      if ((ret = unlock_blocks_add_reference(&tx->unlock_blocks, (uint16_t)pub_index))) {
        printf("[%s:%d] Add reference block failed\n", __func__, __LINE__);
        break;
      }
    }
  }
#endif
  if (b_essence) {
    free(b_essence);
  }
  return ret;
}

void core_message_free(core_message_t* msg) {
  if (msg) {
    if (msg->payload) {
      if (msg->payload_type == CORE_MESSAGE_PAYLOAD_TRANSACTION) {
        tx_payload_free((transaction_payload_t*)msg->payload);
      }
      if (msg->payload_type == CORE_MESSAGE_PAYLOAD_INDEXATION) {
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

char* core_message_get_parent_id(core_message_t* msg, size_t index) {
  if (msg) {
    if (msg->parents && (index < core_message_parent_len(msg))) {
      return *(char**)utarray_eltptr(msg->parents, index);
    }
  }
  return NULL;
}

core_message_payload_type_t core_message_get_payload_type(core_message_t* msg) {
  if (msg) {
    return msg->payload_type;
  }
  return CORE_MESSAGE_PAYLOAD_UNKNOWN;
}

void core_message_print(core_message_t* msg, uint8_t indentation) {
  printf("%sMessage: [\n", PRINT_INDENTATION(indentation));

  if (msg) {
    printf("%sNetwork Id: %" PRIu64 "\n", PRINT_INDENTATION(indentation + 1), msg->network_id);

    printf("%sParent Message Ids:\n", PRINT_INDENTATION(indentation + 1));
    size_t parent_message_len = core_message_parent_len(msg);
    printf("%s\tParent Message Count: %lu\n", PRINT_INDENTATION(indentation + 1), parent_message_len);
    for (size_t index = 0; index < parent_message_len; index++) {
      printf("%s\t#%lu %s\n", PRINT_INDENTATION(indentation + 1), index, core_message_get_parent_id(msg, index));
    }

    switch (msg->payload_type) {
      case CORE_MESSAGE_PAYLOAD_TRANSACTION:
        tx_payload_print((transaction_payload_t*)msg->payload, indentation + 1);
        break;
      default:
        // TODO print other message payloads
        break;
    }

    printf("%sNonce: %" PRIu64 "\n", PRINT_INDENTATION(indentation + 1), msg->nonce);
  }

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
