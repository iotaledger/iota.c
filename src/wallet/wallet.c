// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "wallet/wallet.h"

// validate path: m/44',/4128',/Account',/Change'
static int validate_pib44_path(char const path[]) {
  int ret = -1;
  char tmp_path[IOTA_ACOUNT_PATH_MAX] = {};
  size_t path_len = strlen(path);
  if (path_len > IOTA_ACOUNT_PATH_MAX - 1 || path_len == 0 || path_len == strlen(iota_bip44_prefix)) {
    printf("[%s:%d] invalid length of path\n", __func__, __LINE__);
    return ret;
  }

  if (memcmp(iota_bip44_prefix, path, strlen(iota_bip44_prefix)) != 0) {
    printf("[%s:%d] invalid path prefix\n", __func__, __LINE__);
    return ret;
  }

  if (strstr(path, "//") != NULL || strstr(path, "''") != NULL || strstr(path, "'H") != NULL ||
      strstr(path, "H'") != NULL || strstr(path, "HH") != NULL || strstr(path, "h") != NULL) {
    printf("[%s:%d] invalid path format\n", __func__, __LINE__);
    return ret;
  }

  // char* index = (char *)path + strlen(iota_bip44_prefix) + 1;
  memcpy(tmp_path, path + strlen(iota_bip44_prefix) + 1, path_len - (strlen(iota_bip44_prefix) + 1));
  char* token = strtok(tmp_path, "/");
  size_t token_count = 0;
  while (token != NULL) {
    char* ptr = NULL;
    // check token format
    if (strncmp(token, "\'", 1) == 0 || strncmp(token, "H", 1) == 0) {
      // invalid format
      printf("[%s:%d] invalid path format\n", __func__, __LINE__);
      break;
    }

    // get value
    unsigned long value = strtoul(token, &ptr, 10);

    // hardened
    if (!(strncmp(ptr, "\'", 1) == 0 || strncmp(ptr, "H", 1) == 0)) {
      // invalid format
      printf("[%s:%d] invalid path format: hardened is needed\n", __func__, __LINE__);
      break;
    }
    // gets next token
    token = strtok(NULL, "/");
    token_count++;
  }

  if (token_count != 2) {
    printf("[%s:%d] path format: m/44'/4218'/Account'/Change'\n", __func__, __LINE__);
  } else {
    ret = 0;
  }
  return ret;
}

iota_wallet_t* wallet_create(byte_t const seed[], char const path[]) {
  if (!seed || !path) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (validate_pib44_path(path)) {
    return NULL;
  }

  iota_wallet_t* w = malloc(sizeof(iota_wallet_t));
  if (w) {
    memcpy(w->seed, seed, IOTA_SEED_BYTES);
    memcpy(w->account, path, strlen(path) + 1);
    strcpy(w->endpoint, "http://localhost:14265/");
    memset(w->endpoint, 0, sizeof(w->endpoint));
    w->port = 0;
  }
  return w;
}

int wallet_get_address(iota_wallet_t* w, uint64_t index, byte_t addr[]) {
  // Use the new seed like a wallet with Bip44 Paths: 44,4128,Account,Change,Index
  return 0;
}

int wallet_get_balance(iota_wallet_t* w, uint64_t* balance) { return 0; }

int wallet_send(iota_wallet_t* w, uint64_t balance, char const index[], char const data[]) { return 0; }

void wallet_destroy(iota_wallet_t* w) {
  if (w) {
    free(w);
  }
}