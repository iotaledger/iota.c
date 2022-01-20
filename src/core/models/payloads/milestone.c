// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/payloads/milestone.h"
#include "core/models/message.h"

milestone_t *payload_milestone_new() {
  milestone_t *ms = malloc(sizeof(milestone_t));
  if (ms) {
    ms->type = MSG_PAYLOAD_MILESTONE;
    ms->index = 0;
    ms->timestamp = 0;
    memset(ms->inclusion_merkle_proof, 0, sizeof(ms->inclusion_merkle_proof));
    utarray_new(ms->signatures, &ut_str_icd);
  }
  return ms;
}

void payload_milestone_free(milestone_t *ms) {
  if (ms) {
    if (ms->signatures) {
      utarray_free(ms->signatures);
    }
    free(ms);
  }
}
