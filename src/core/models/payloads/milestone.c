// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/payloads/milestone.h"
#include "core/constants.h"
#include "core/models/message.h"
#include "core/utils/macros.h"
#include "utlist.h"

static const UT_icd ut_blk_id_icd = {sizeof(uint8_t) * IOTA_BLOCK_ID_BYTES, NULL, NULL, NULL};
static const UT_icd ut_sign_icd = {sizeof(uint8_t) * ED25519_SIGNATURE_BLOCK_BYTES, NULL, NULL, NULL};

milestone_payload_t *milestone_payload_new() {
  milestone_payload_t *ms = malloc(sizeof(milestone_payload_t));
  if (ms) {
    ms->type = CORE_BLOCK_PAYLOAD_MILESTONE;
    ms->index = 0;
    ms->timestamp = 0;
    ms->protocol_version = 0;
    memset(ms->previous_milestone_id, 0, sizeof(ms->previous_milestone_id));
    utarray_new(ms->parents, &ut_blk_id_icd);
    memset(ms->confirmed_merkle_root, 0, sizeof(ms->confirmed_merkle_root));
    memset(ms->applied_merkle_root, 0, sizeof(ms->applied_merkle_root));
    ms->metadata = NULL;
    ms->options = NULL;
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
    if (ms->options) {
      milestone_options_list_t *elm, *tmp;
      LL_FOREACH_SAFE(ms->options, elm, tmp) {
        if (elm->option) {
          if (elm->option->option) {
            free(elm->option->option);
          }
          free(elm->option);
        }
        LL_DELETE(ms->options, elm);
        free(elm);
      }
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

    if (ms->protocol_version > 0) {
      printf("%s\tProtocol Version: %d\n", PRINT_INDENTATION(indentation), ms->protocol_version);
    }

    printf("%s\tPrevious Milestone Id: ", PRINT_INDENTATION(indentation));
    dump_hex_str(ms->previous_milestone_id, sizeof(ms->previous_milestone_id));

    printf("%s\tParent Block Ids:\n", PRINT_INDENTATION(indentation));
    size_t parent_block_len = milestone_payload_get_parents_count(ms);
    printf("%s\tParent Block Count: %zu\n", PRINT_INDENTATION(indentation + 1), parent_block_len);
    for (size_t index = 0; index < parent_block_len; index++) {
      printf("%s\t#%zu ", PRINT_INDENTATION(indentation + 1), index);
      dump_hex_str(milestone_payload_get_parent(ms, index), IOTA_BLOCK_ID_BYTES);
    }

    printf("%s\tConfirmed Merkle Root: ", PRINT_INDENTATION(indentation));
    dump_hex_str(ms->confirmed_merkle_root, sizeof(ms->confirmed_merkle_root));

    printf("%s\tApplied Merkle Root: ", PRINT_INDENTATION(indentation));
    dump_hex_str(ms->applied_merkle_root, sizeof(ms->applied_merkle_root));

    if (ms->metadata) {
      printf("%s\tMetadata: ", PRINT_INDENTATION(indentation));
      dump_hex_str(ms->metadata->data, ms->metadata->len);
    } else {
      printf("%s\tMetadata:\n", PRINT_INDENTATION(indentation));
    }

    if (ms->options) {
      printf("%s\tOptions: [\n", PRINT_INDENTATION(indentation));
      milestone_options_list_t *elm;
      uint8_t milestone_option_index = 0;
      LL_FOREACH(ms->options, elm) {
        printf("%s\t\t#%d\n", PRINT_INDENTATION(indentation), milestone_option_index);
        switch (elm->option->type) {
          case MILESTONE_OPTION_RECEIPTS:
            break;
          case MILESTONE_OPTION_POW:
            printf("%s\t\t\tType: Milestone PoW Option\n", PRINT_INDENTATION(indentation));
            printf("%s\t\t\tNext POW Score: %d\n", PRINT_INDENTATION(indentation),
                   ((milestone_pow_option_t *)elm->option->option)->next_pow_score);
            printf("%s\t\t\tNext POW Score Milestone Index: %d\n", PRINT_INDENTATION(indentation),
                   ((milestone_pow_option_t *)elm->option->option)->next_pow_score_milestone_index);
            break;
        }
      }
      printf("%s\t]\n", PRINT_INDENTATION(indentation));
    } else {
      printf("%s\tOptions: []\n", PRINT_INDENTATION(indentation));
    }

    printf("%s\tSignatures: [\n", PRINT_INDENTATION(indentation));
    size_t signatures_len = milestone_payload_get_signatures_count(ms);
    printf("%s\tSignatures Count: %zu\n", PRINT_INDENTATION(indentation + 1), signatures_len);
    for (size_t index = 0; index < signatures_len; index++) {
      printf("%s\t#%zu\n", PRINT_INDENTATION(indentation + 1), index);
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
