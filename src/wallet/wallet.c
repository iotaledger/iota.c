// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "client/api/v1/get_balance.h"
#include "core/utils/byte_buffer.h"
#include "wallet/wallet.h"

// TODO: move to utils?
// validate path: m/44',/4128',/Account',/Change'
static int validate_pib44_path(char const path[]) {
  int ret = -1;
  char tmp_path[IOTA_ACCOUNT_PATH_MAX] = {};
  size_t path_len = strlen(path);
  if (path_len > IOTA_ACCOUNT_PATH_MAX - 1 || path_len == 0 || path_len == strlen(iota_bip44_prefix)) {
    printf("[%s:%d] Err: invalid length of path\n", __func__, __LINE__);
    return ret;
  }

  if (memcmp(iota_bip44_prefix, path, strlen(iota_bip44_prefix)) != 0) {
    printf("[%s:%d] Err: invalid path prefix\n", __func__, __LINE__);
    return ret;
  }

  if (strstr(path, "//") != NULL || strstr(path, "''") != NULL || strstr(path, "'H") != NULL ||
      strstr(path, "H'") != NULL || strstr(path, "HH") != NULL || strstr(path, "h") != NULL) {
    printf("[%s:%d] Err: invalid path format\n", __func__, __LINE__);
    return ret;
  }

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
      printf("[%s:%d] Err: invalid path format: hardened is needed\n", __func__, __LINE__);
      break;
    }
    // gets next token
    token = strtok(NULL, "/");
    token_count++;
  }

  if (token_count != 2) {
    printf("[%s:%d] Err: path format is m/44'/4218'/Account'/Change'\n", __func__, __LINE__);
  } else {
    ret = 0;
  }
  return ret;
}

iota_wallet_t* wallet_create(byte_t const seed[], char const path[]) {
  if (!seed || !path) {
    printf("[%s:%d] Err: invalid parameters\n", __func__, __LINE__);
    return NULL;
  }

  if (validate_pib44_path(path)) {
    return NULL;
  }

  iota_wallet_t* w = malloc(sizeof(iota_wallet_t));
  if (w) {
    memcpy(w->seed, seed, IOTA_SEED_BYTES);
    memcpy(w->account, path, strlen(path) + 1);
    strcpy(w->endpoint.url, "http://localhost:14265/");
    w->endpoint.port = 0;
  }
  return w;
}

int wallet_set_endpoint(iota_wallet_t* w, char const url[], uint16_t port) {
  if (!w || !url) {
    printf("[%s:%d] Err: invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(url) >= sizeof(w->endpoint.url)) {
    printf("[%s:%d] Err: The length of URL is too long\n", __func__, __LINE__);
    return -1;
  }

  strncpy(w->endpoint.url, url, sizeof(w->endpoint.url) - 1);
  w->endpoint.port = port;
  return 0;
}

int wallet_address_by_index(iota_wallet_t* w, uint64_t index, byte_t addr[]) {
  if (!w || !addr) {
    printf("[%s:%d] Err: invalid parameters\n", __func__, __LINE__);
    return -1;
  }
  char path_buf[IOTA_ACCOUNT_PATH_MAX] = {};
  // Bip44 Paths: m/44'/4128'/Account'/Change'/Index'
  sprintf(path_buf, "%s/%" PRIu64 "'", w->account, index);
  return address_from_path(w->seed, path_buf, addr);
}

int wallet_balance_by_address(iota_wallet_t* w, byte_t const addr[], uint64_t* balance) {
  char hex_addr[ED25519_ADDRESS_BYTES * 2 + 1] = {};
  res_balance_t* bal_res = NULL;

  // binary address to hex string
  if (bin2hex(addr, ED25519_ADDRESS_BYTES, hex_addr, sizeof(hex_addr))) {
    printf("[%s:%d] Err: Convert binary address to hex string failed\n", __func__, __LINE__);
    return -1;
  }

  if ((bal_res = res_balance_new()) == NULL) {
    printf("[%s:%d] Err: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (get_balance(&w->endpoint, hex_addr, bal_res)) {
    printf("[%s:%d] Err: ge balance API failed\n", __func__, __LINE__);
    if (bal_res->is_error) {
      printf("Err response: %s\n", bal_res->u.error->msg);
    }
    res_balance_free(bal_res);
    return -1;
  }

  *balance = bal_res->u.output_balance->balance;
  res_balance_free(bal_res);
  return 0;
}

int wallet_balance_by_index(iota_wallet_t* w, uint64_t index, uint64_t* balance) {
  byte_t addr[ED25519_ADDRESS_BYTES] = {};
  int ret = wallet_address_by_index(w, index, addr);
  if (ret == 0) {
    ret = wallet_balance_by_address(w, addr, balance);
  }
  return ret;
}

int wallet_send(iota_wallet_t* w, byte_t addr[], uint64_t balance, char const index[], char const data[]) { return 0; }

void wallet_destroy(iota_wallet_t* w) {
  if (w) {
    free(w);
  }
}