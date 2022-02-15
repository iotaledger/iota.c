// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/payloads/milestone.h"
#include "core/models/message.h"

static const UT_icd ut_msg_id_icd = {sizeof(uint8_t) * IOTA_MESSAGE_ID_BYTES, NULL, NULL, NULL};
static const UT_icd ut_pub_key_icd = {sizeof(uint8_t) * MILESTONE_PUBLIC_KEY_LENGTH, NULL, NULL, NULL};
static const UT_icd ut_sign_icd = {sizeof(uint8_t) * MILESTONE_SIGNATURE_LENGTH, NULL, NULL, NULL};

milestone_t *milestone_payload_new() {
  milestone_t *ms = malloc(sizeof(milestone_t));
  if (ms) {
    ms->type = CORE_MESSAGE_PAYLOAD_MILESTONE;
    ms->index = 0;
    ms->timestamp = 0;
    utarray_new(ms->parents, &ut_msg_id_icd);
    memset(ms->inclusion_merkle_proof, 0, sizeof(ms->inclusion_merkle_proof));
    ms->next_pow_score = 0;
    ms->next_pow_score_milestone_index = 0;
    utarray_new(ms->pub_keys, &ut_pub_key_icd);
    ms->receipt = NULL;
    utarray_new(ms->signatures, &ut_sign_icd);
  }
  return ms;
}

void milestone_payload_free(milestone_t *ms) {
  if (ms) {
    if (ms->parents) {
      utarray_free(ms->parents);
    }
    if (ms->pub_keys) {
      utarray_free(ms->pub_keys);
    }
    if (ms->signatures) {
      utarray_free(ms->signatures);
    }
    free(ms);
  }
}

size_t milestone_payload_get_parents_count(milestone_t *ms) {
  if (ms) {
    return utarray_len(ms->parents);
  }
  return 0;
}

byte_t *milestone_payload_get_parent(milestone_t *ms, size_t index) {
  if (ms) {
    if (ms->parents && (index < milestone_payload_get_parents_count(ms))) {
      return utarray_eltptr(ms->parents, index);
    }
  }
  return NULL;
}

size_t milestone_payload_get_pub_keys_count(milestone_t *ms) {
  if (ms) {
    return utarray_len(ms->pub_keys);
  }
  return 0;
}

byte_t *milestone_payload_get_pub_key(milestone_t *ms, size_t index) {
  if (ms) {
    if (ms->pub_keys && (index < milestone_payload_get_pub_keys_count(ms))) {
      return utarray_eltptr(ms->pub_keys, index);
    }
  }
  return NULL;
}

size_t milestone_payload_get_signatures_count(milestone_t *ms) {
  if (ms) {
    return utarray_len(ms->signatures);
  }
  return 0;
}

byte_t *milestone_payload_get_signature(milestone_t *ms, size_t index) {
  if (ms) {
    if (ms->signatures && (index < milestone_payload_get_signatures_count(ms))) {
      return utarray_eltptr(ms->signatures, index);
    }
  }
  return NULL;
}
