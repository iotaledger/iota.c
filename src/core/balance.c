#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/balance.h"
#include "libbase58.h"

static bool empty_color(byte_t color[]) {
  for (int i = 0; i < BALANCE_COLOR_BYTES; i++) {
    if (color[i] != 0) {
      return false;
    }
  }
  return true;
}

bool balance_color_2_base58(char color_str[], byte_t color[]) {
  size_t buf_len = BALANCE_COLOR_BASE58_LEN;
  bool ret = true;
  if (empty_color(color)) {
    snprintf(color_str, buf_len, "IOTA");
  } else {
    ret = b58enc(color_str, &buf_len, (const void*)color, BALANCE_COLOR_BYTES);
    // printf("len %zu, %d\n", buf_len, ret);
  }
  return ret;
}

void balance_init(balance_t* balance, byte_t color[], int64_t value) {
  balance->value = value;
  memset(balance->color, 0, BALANCE_COLOR_BYTES);
  if (color) {
    balance_set_color(balance, color);
  }
}

void balance_from_bytes(balance_t* balance, byte_t balance_bytes[]) {
  memcpy(&balance->value, balance_bytes, sizeof(balance->value));
  memcpy(balance->color, balance_bytes + sizeof(balance->value), sizeof(balance->color));
}

void balance_set_color(balance_t* balance, byte_t color[]) { memcpy(balance->color, color, BALANCE_COLOR_BYTES); }

void balance_2_bytes(byte_t balance_bytes[], balance_t* balance) {
  // value offset
  int offset = sizeof(balance->value);
  memcpy(balance_bytes, &balance->value, offset);
  memcpy(balance_bytes + offset, balance->color, sizeof(balance->color));
}

void print_balance(balance_t* balance) {
  if (empty_color(balance->color)) {
    char color_str[BALANCE_COLOR_BASE58_LEN];
    balance_color_2_base58(color_str, balance->color);
    printf("balance[%" PRId64 ", %s]\n", balance->value, color_str);
  } else {
    printf("balance[%" PRId64 ", IOTA]\n", balance->value);
  }
}
