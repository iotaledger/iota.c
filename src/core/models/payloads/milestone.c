// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/payloads/milestone.h"
#include "core/models/message.h"
#include "core/models/unlock_block.h"

static const UT_icd ut_msg_id_icd = {sizeof(uint8_t) * IOTA_MESSAGE_ID_BYTES, NULL, NULL, NULL};
static const UT_icd ut_sign_icd = {sizeof(uint8_t) * ED25519_SIGNATURE_BLOCK_BYTES, NULL, NULL, NULL};

milestone_payload_t *milestone_payload_new() {
  milestone_payload_t *ms = malloc(sizeof(milestone_payload_t));
  if (ms) {
    ms->type = CORE_MESSAGE_PAYLOAD_MILESTONE;
    ms->index = 0;
    ms->timestamp = 0;
    utarray_new(ms->parents, &ut_msg_id_icd);
    memset(ms->inclusion_merkle_proof, 0, sizeof(ms->inclusion_merkle_proof));
    ms->next_pow_score = 0;
    ms->next_pow_score_milestone_index = 0;
    ms->metadata = NULL;
    ms->receipt = NULL;
    utarray_new(ms->signatures, &ut_sign_icd);
  }
  return ms;
}

void milestone_payload_free(milestone_payload_t *ms) {
  if (ms) {
    if (ms->parents) {
      utarray_free(ms->parents);
    }
    if (ms->metadata) {
      byte_buf_free(ms->metadata);
    }
    if (ms->signatures) {
      utarray_free(ms->signatures);
    }
    free(ms);
  }
}

size_t milestone_payload_get_parents_count(milestone_payload_t *ms) {
  if (ms) {
    return utarray_len(ms->parents);
  }
  return 0;
}

byte_t *milestone_payload_get_parent(milestone_payload_t *ms, size_t index) {
  if (ms) {
    if (ms->parents && (index < milestone_payload_get_parents_count(ms))) {
      return utarray_eltptr(ms->parents, index);
    }
  }
  return NULL;
}

size_t milestone_payload_get_signatures_count(milestone_payload_t *ms) {
  if (ms) {
    return utarray_len(ms->signatures);
  }
  return 0;
}

byte_t *milestone_payload_get_signature(milestone_payload_t *ms, size_t index) {
  if (ms) {
    if (ms->signatures && (index < milestone_payload_get_signatures_count(ms))) {
      return utarray_eltptr(ms->signatures, index);
    }
  }
  return NULL;
}

void milestone_payload_print(milestone_payload_t *ms, uint8_t indentation) {
  if (ms) {
    printf("%sMilestone: [\n", PRINT_INDENTATION(indentation));

    printf("%s\tIndex: %d\n", PRINT_INDENTATION(indentation), ms->index);
    printf("%s\tTimestamp: %d\n", PRINT_INDENTATION(indentation), ms->timestamp);

    printf("%s\tParent Message Ids:\n", PRINT_INDENTATION(indentation));
    size_t parent_message_len = milestone_payload_get_parents_count(ms);
    printf("%s\tParent Message Count: %lu\n", PRINT_INDENTATION(indentation + 1), parent_message_len);
    for (size_t index = 0; index < parent_message_len; index++) {
      printf("%s\t#%lu ", PRINT_INDENTATION(indentation + 1), index);
      dump_hex_str(milestone_payload_get_parent(ms, index), IOTA_MESSAGE_ID_BYTES);
    }

    printf("%s\tInclusion Merkle Proof: ", PRINT_INDENTATION(indentation));
    dump_hex_str(ms->inclusion_merkle_proof, sizeof(ms->inclusion_merkle_proof));

    printf("%s\tNext POW Score: %d\n", PRINT_INDENTATION(indentation), ms->next_pow_score);
    printf("%s\tNext POW Score Milestone Index: %d\n", PRINT_INDENTATION(indentation),
           ms->next_pow_score_milestone_index);

    if (ms->metadata) {
      printf("%s\tMetadata: ", PRINT_INDENTATION(indentation));
      dump_hex_str(ms->metadata->data, ms->metadata->len);
    } else {
      printf("%s\tMetadata: null\n", PRINT_INDENTATION(indentation));
    }

    // TODO print receipt
    printf("%s\tReceipt: null\n", PRINT_INDENTATION(indentation));

    printf("%s\tSignatures: [\n", PRINT_INDENTATION(indentation));
    size_t signatures_len = milestone_payload_get_signatures_count(ms);
    printf("%s\tSignatures Count: %lu\n", PRINT_INDENTATION(indentation + 1), signatures_len);
    for (size_t index = 0; index < signatures_len; index++) {
      printf("%s\t#%lu\n", PRINT_INDENTATION(indentation + 1), index);
      byte_t *signature = milestone_payload_get_signature(ms, index);
      printf("%s\t\t\tType: %s\n", PRINT_INDENTATION(indentation), signature[0] ? "UNKNOWN" : "ED25519");
      printf("%s\t\t\tPub key: ", PRINT_INDENTATION(indentation));
      dump_hex_str(signature + 1, ED_PUBLIC_KEY_BYTES);
      printf("%s\t\t\tSignature: ", PRINT_INDENTATION(indentation));
      dump_hex_str(signature + 1 + ED_PUBLIC_KEY_BYTES, ED_SIGNATURE_BYTES);
    }
    printf("%s]\n", PRINT_INDENTATION(indentation + 1));

    printf("%s]\n", PRINT_INDENTATION(indentation));
  } else {
    printf("%sMilestone: []\n", PRINT_INDENTATION(indentation));
  }
}
