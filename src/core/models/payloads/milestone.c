// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/payloads/milestone.h"
#include "core/models/message.h"

milestone_t *milestone_payload_new() {
  milestone_t *ms = malloc(sizeof(milestone_t));
  if (ms) {
    ms->type = CORE_MESSAGE_PAYLOAD_MILESTONE;
    ms->index = 0;
    ms->timestamp = 0;
    memset(ms->inclusion_merkle_proof, 0, sizeof(ms->inclusion_merkle_proof));
    utarray_new(ms->signatures, &ut_str_icd);
  }
  return ms;
}

void milestone_payload_free(milestone_t *ms) {
  if (ms) {
    if (ms->signatures) {
      utarray_free(ms->signatures);
    }
    free(ms);
  }
}

size_t milestone_payload_get_signature_count(milestone_t *ms) {
  if (ms) {
    return utarray_len(ms->signatures);
  }
  return 0;
}

char *milestone_payload_get_signature(milestone_t *ms, size_t index) {
  if (ms) {
    if (utarray_len(ms->signatures)) {
      char **p = (char **)utarray_eltptr(ms->signatures, index);
      return *p;
    }
  }
  return NULL;
}
