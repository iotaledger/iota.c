// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/models/message.h"
#include "core/models/payloads/tagged_data.h"
#include "core/models/payloads/transaction.h"
#include "utlist.h"

static const UT_icd ut_msg_id_icd = {sizeof(uint8_t) * IOTA_MESSAGE_ID_BYTES, NULL, NULL, NULL};

core_message_t* core_message_new(uint8_t ver) {
  core_message_t* msg = malloc(sizeof(core_message_t));
  if (msg) {
    msg->protocol_version = ver;
    utarray_new(msg->parents, &ut_msg_id_icd);
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

  utxo_inputs_list_t* elm;
  LL_FOREACH(tx->essence->inputs, elm) {
    if (elm->input->keypair) {
      int32_t pub_index = unlock_blocks_find_pub(tx->unlock_blocks, elm->input->keypair->pub);
      if (pub_index == -1) {
        // publick key is not found in the unlocked block
        byte_t sig_block[ED25519_SIGNATURE_BLOCK_BYTES] = {};
        sig_block[0] = ADDRESS_TYPE_ED25519;
        memcpy(sig_block + 1, elm->input->keypair->pub, ED_PUBLIC_KEY_BYTES);
        // sign transaction
        if ((ret = iota_crypto_sign(elm->input->keypair->priv, essence_hash, CRYPTO_BLAKE2B_HASH_BYTES,
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
  }
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
      } else if (msg->payload_type == CORE_MESSAGE_PAYLOAD_MILESTONE) {
        milestone_payload_free((milestone_payload_t*)msg->payload);
      } else if (msg->payload_type == CORE_MESSAGE_PAYLOAD_TAGGED) {
        tagged_data_free((tagged_data_payload_t*)msg->payload);
      } else {
        printf("[%s:%d] unsupported payload type\n", __func__, __LINE__);
      }
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

byte_t* core_message_get_parent_id(core_message_t* msg, size_t index) {
  if (msg) {
    if (msg->parents && (index < core_message_parent_len(msg))) {
      return utarray_eltptr(msg->parents, index);
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

size_t core_message_serialize_len(core_message_t* msg) {
  if (msg == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t length = 0;

  // protocol version
  length += sizeof(uint8_t);
  // parents count
  length += sizeof(uint8_t);
  // parents
  length += core_message_parent_len(msg) * IOTA_MESSAGE_ID_BYTES;
  // payload length
  length += sizeof(uint32_t);

  // payload
  switch (msg->payload_type) {
    case CORE_MESSAGE_PAYLOAD_TRANSACTION:
      length += tx_payload_serialize_length((transaction_payload_t*)msg->payload);
      break;
    case CORE_MESSAGE_PAYLOAD_TAGGED:
      length += tagged_data_serialize_len((tagged_data_payload_t*)(msg->payload));
      break;
    case CORE_MESSAGE_PAYLOAD_MILESTONE:
    case CORE_MESSAGE_PAYLOAD_INDEXATION:
    case CORE_MESSAGE_PAYLOAD_RECEIPT:
    case CORE_MESSAGE_PAYLOAD_TREASURY:
    default:
      printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
      return 0;
  }

  // nonce
  length += sizeof(uint64_t);

  return length;
}

size_t core_message_serialize(core_message_t* msg, byte_t buf[], size_t buf_len) {
  if (msg == NULL || buf == NULL || buf_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return 0;
  }

  size_t expected_bytes = core_message_serialize_len(msg);
  if (buf_len < expected_bytes) {
    printf("[%s:%d] buffer size is insufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;

  // protocol version
  memcpy(buf, &msg->protocol_version, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // parents count
  uint8_t parents_len = (uint8_t)core_message_parent_len(msg);
  memset(buf + offset, parents_len, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  // parents
  for (uint8_t index = 0; index < parents_len; index++) {
    byte_t* parent_id = core_message_get_parent_id(msg, index);
    memcpy(buf + offset, parent_id, IOTA_MESSAGE_ID_BYTES);
    offset += IOTA_MESSAGE_ID_BYTES;
  }

  // payload length
  uint32_t payload_len = 0;
  switch (msg->payload_type) {
    case CORE_MESSAGE_PAYLOAD_TRANSACTION:
      payload_len = (uint32_t)tx_payload_serialize_length((transaction_payload_t*)msg->payload);
      break;
    case CORE_MESSAGE_PAYLOAD_TAGGED:
      payload_len = (uint32_t)tagged_data_serialize_len((tagged_data_payload_t*)(msg->payload));
      break;
    case CORE_MESSAGE_PAYLOAD_MILESTONE:
    case CORE_MESSAGE_PAYLOAD_INDEXATION:
    case CORE_MESSAGE_PAYLOAD_RECEIPT:
    case CORE_MESSAGE_PAYLOAD_TREASURY:
    default:
      printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
      return 0;
  }
  memcpy(buf + offset, &payload_len, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  // payload
  switch (msg->payload_type) {
    case CORE_MESSAGE_PAYLOAD_TRANSACTION:
      offset += tx_payload_serialize((transaction_payload_t*)msg->payload, buf + offset, buf_len - offset);
      break;
    case CORE_MESSAGE_PAYLOAD_TAGGED:
      offset += tagged_data_serialize((tagged_data_payload_t*)msg->payload, buf + offset, buf_len - offset);
      break;
    case CORE_MESSAGE_PAYLOAD_MILESTONE:
    case CORE_MESSAGE_PAYLOAD_INDEXATION:
    case CORE_MESSAGE_PAYLOAD_RECEIPT:
    case CORE_MESSAGE_PAYLOAD_TREASURY:
    default:
      printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
      return 0;
  }

  // nonce
  memcpy(buf + offset, &msg->nonce, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  return offset;
}

void core_message_print(core_message_t* msg, uint8_t indentation) {
  printf("%sMessage: [\n", PRINT_INDENTATION(indentation));

  if (msg) {
    printf("%sProtocol Version: %d\n", PRINT_INDENTATION(indentation + 1), msg->protocol_version);

    printf("%sParent Message Ids:\n", PRINT_INDENTATION(indentation + 1));
    size_t parent_message_len = core_message_parent_len(msg);
    printf("%s\tParent Message Count: %lu\n", PRINT_INDENTATION(indentation + 1), parent_message_len);
    for (size_t index = 0; index < parent_message_len; index++) {
      printf("%s\t#%lu ", PRINT_INDENTATION(indentation + 1), index);
      dump_hex_str(core_message_get_parent_id(msg, index), IOTA_MESSAGE_ID_BYTES);
    }

    switch (msg->payload_type) {
      case CORE_MESSAGE_PAYLOAD_TRANSACTION:
        tx_payload_print((transaction_payload_t*)msg->payload, indentation + 1);
        break;
      case CORE_MESSAGE_PAYLOAD_MILESTONE:
        milestone_payload_print((milestone_payload_t*)msg->payload, indentation + 1);
        break;
      case CORE_MESSAGE_PAYLOAD_INDEXATION:
      case CORE_MESSAGE_PAYLOAD_RECEIPT:
      case CORE_MESSAGE_PAYLOAD_TREASURY:
        printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
        break;
      case CORE_MESSAGE_PAYLOAD_TAGGED:
        tagged_data_print((tagged_data_payload_t*)msg->payload, indentation + 1);
        break;
      default:
        printf("[%s:%d]: unsupported payload type\n", __func__, __LINE__);
        break;
    }

    printf("%sNonce: %" PRIu64 "\n", PRINT_INDENTATION(indentation + 1), msg->nonce);
  }

  printf("%s]\n", PRINT_INDENTATION(indentation));
}
