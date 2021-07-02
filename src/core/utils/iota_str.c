// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/utils/iota_str.h"
#include "core/utils/allocator.h"

iota_str_t *iota_str_new(char const s[]) {
  iota_str_t *istr = malloc(sizeof(iota_str_t));
  if (!istr) {
    return NULL;
  }

  istr->len = strlen(s);
  istr->cap = istr->len + 1;
  istr->buf = malloc(istr->cap);
  if (!istr->buf) {
    free(istr);
    return NULL;
  }

  memcpy(istr->buf, s, istr->len);
  istr->buf[istr->len] = '\0';
  return istr;
}

void iota_str_destroy(iota_str_t *istr) {
  if (istr) {
    if (istr->buf) {
      free(istr->buf);
    }
    free(istr);
  }
}

int iota_str_appendn(iota_str_t *istr, char const s[], size_t len) {
  // needed capacity
  size_t needed_cap = istr->len + len + 1;

  if (needed_cap > istr->cap) {
    // request more buffer
    istr->buf = realloc(istr->buf, needed_cap);
    if (istr->buf == NULL) {
      return -1;
    }
    istr->cap = needed_cap;
  }

  // copy c_string to buffer
  memcpy(istr->buf + istr->len, s, len);
  istr->len += len;
  // append terminator
  istr->buf[istr->len] = '\0';
  return 0;
}

iota_str_t *iota_str_clonen(iota_str_t *istr, size_t len) {
  iota_str_t *clone = malloc(sizeof(iota_str_t));
  if (!clone) {
    return NULL;
  }

  clone->len = len;
  clone->cap = len + 1;
  clone->buf = malloc(istr->cap);
  if (!clone->buf) {
    free(clone);
    return NULL;
  }

  memcpy(clone->buf, istr->buf, len);
  clone->buf[clone->len] = '\0';
  return clone;
}

iota_str_t *iota_str_reserve(size_t len) {
  iota_str_t *istr = malloc(sizeof(iota_str_t));
  if (!istr) {
    return NULL;
  }

  istr->len = 0;
  istr->cap = len;
  istr->buf = malloc(istr->cap);
  if (!istr->buf) {
    free(istr);
    return NULL;
  }

  return istr;
}