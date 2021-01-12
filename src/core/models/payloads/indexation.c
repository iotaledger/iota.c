#include <inttypes.h>
#include <stdio.h>

#include "core/models/payloads/indexation.h"

indexation_t *indexation_new() {
  indexation_t *idx = malloc(sizeof(indexation_t));
  if (idx) {
    idx->type = 2;
    if ((idx->data = byte_buf_new())) {
      if ((idx->index = byte_buf_new)) {
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

void indexation_free(indexation_t *idx) {
  if (idx) {
    byte_buf_free(idx->data);
    byte_buf_free(idx->index);
    free(idx);
  }
}

indexation_t *indexation_create(char index[], byte_t *data, size_t data_size) {
  indexation_t *idx = NULL;
  if ((idx = indexation_new()) != NULL) {
    // add index string
    if (!byte_buf_append(idx->index, index, strlen(index) + 1)) {
      printf("[%s:%d] append index failed", __func__, __LINE__);
      indexation_free(idx);
      return NULL;
    }
    // add data bytes
    if (!byte_buf_append(idx->data, data, data_size)) {
      printf("[%s:%d] append data failed", __func__, __LINE__);
      indexation_free(idx);
      return NULL;
    }
    return idx;
  }
  return NULL;
}
