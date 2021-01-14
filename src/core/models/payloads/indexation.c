// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "core/models/payloads/indexation.h"

indexation_t *indexation_new() {
  indexation_t *idx = malloc(sizeof(indexation_t));
  if (idx) {
    idx->index = NULL;
    idx->data = NULL;
  }
  return idx;
}

void indexation_free(indexation_t *idx) {
  if (idx) {
    byte_buf_free(idx->data);
    byte_buf_free(idx->index);
    free(idx);
  }
}

indexation_t *indexation_create(char const *index, char const *data) {
  indexation_t *idx = NULL;

  if ((idx = indexation_new()) != NULL) {
    // add index string
    idx->index = byte_buf_new_with_data((byte_t *)index, strlen(index) + 1);
    if (!idx->index) {
      printf("[%s:%d] append index failed", __func__, __LINE__);
      indexation_free(idx);
      return NULL;
    }

    // add a hex string to data
    idx->data = byte_buf_new_with_data((byte_t *)data, strlen(data) + 1);
    if (!idx->data) {
      printf("[%s:%d] append data failed", __func__, __LINE__);
      indexation_free(idx);
      return NULL;
    }
  }
  return idx;
}
