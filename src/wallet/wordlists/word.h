// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __WALLE__WORDLISTS_WORD_H__
#define __WALLE__WORDLISTS_WORD_H__

#include <stdlib.h>

/**
 * @brief The word object for wordlist tables.
 *
 */
typedef struct word {
  char *p;     ///< a pointer to the string
  size_t len;  ///< the length of string, null terminator is excluded
} word_t;

#endif