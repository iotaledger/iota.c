// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <string.h>

#include "core/utils/allocator.h"
#include "core/utils/byte_buffer.h"

static char const* const hex_table = "0123456789ABCDEF";

static int char2int(char input) {
  if (input >= '0' && input <= '9') return input - '0';
  if (input >= 'A' && input <= 'F') return input - 'A' + 10;
  if (input >= 'a' && input <= 'f') return input - 'a' + 10;
  return -1;  // invalid char
}

static int int2char(uint8_t input) {
  if (input <= 9) return input + '0';
  if (input <= 15) return input - 10 + 'A';
  return -1;  // invalid value
}

int hex2string(char const str[], uint8_t array[], size_t arr_len) {
  size_t len = strlen(str) / 2;
  if (arr_len < len) {
    // buffer size is not sufficient
    return -1;
  }

  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') {
      c += (str[i * 2] - '0') << 4;
    }
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F') {
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    }
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
      c += (str[i * 2 + 1] - '0');
    }
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') {
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    }
    array[i] = c;
  }
  return 0;
}

int string2hex(char const str[], byte_t hex[], size_t hex_len) {
  size_t required_size = strlen(str) * 2 + 1;
  if (hex_len < required_size) {
    // hex buffer size is not sufficient
    return -1;
  }

  size_t hex_index = 0;
  for (size_t i = 0; i < strlen(str); i++) {
    hex[i * 2 + 0] = hex_table[(str[i] >> 4) & 0x0F];
    hex[i * 2 + 1] = hex_table[(str[i]) & 0x0F];
    hex_index += 2;
  }
  hex[hex_index] = '\0';
  return 0;
}

int hex_2_bin(char const str[], size_t str_len, byte_t bin[], size_t bin_len) {
  if (!str || !bin) {
    return -1;
  }

  size_t expected_bin_len = str_len / 2;
  if (bin_len < expected_bin_len) {
    // buffer size is not sufficient
    return -2;
  }

  char* pos = (char*)str;
  for (size_t i = 0; i < expected_bin_len; i++) {
    int v_h = char2int(pos[0]);
    int v_l = char2int(pos[1]);
    if (v_h < 0 || v_l < 0) {
      // invalid char
      return -3;
    }
    bin[i] = v_h * 16 + v_l;
    pos += 2;
  }
  return 0;
}

int bin_2_hex(byte_t const bin[], size_t bin_len, char str_buf[], size_t buf_len) {
  size_t index = 0;
  if (buf_len < ((bin_len * 2) + 1)) {
    // buffer too small
    return -1;
  }

  for (size_t i = 0; i < bin_len; i++) {
    int v_h = int2char((bin[i] >> 4) & 0x0F);
    int v_l = int2char(bin[i] & 0x0F);
    if (v_h < 0 || v_l < 0) {
      // invalid value
      return -2;
    }
    str_buf[index] = v_h;
    str_buf[index + 1] = v_l;
    index += 2;
  }
  str_buf[index] = '\0';
  return 0;
}

byte_buf_t* byte_buf_new() {
  byte_buf_t* buf = malloc(sizeof(byte_buf_t));
  if (buf) {
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
  }
  return buf;
}

byte_buf_t* byte_buf_new_with_data(byte_t data[], size_t len) {
  if (data == NULL) {
    return NULL;
  }

  byte_buf_t* buf = malloc(sizeof(byte_buf_t));
  if (buf) {
    buf->data = malloc(len);
    if (buf->data) {
      memcpy(buf->data, data, len);
      buf->len = len;
      buf->cap = len;
    } else {
      // Out of Memory
      free(buf);
      return NULL;
    }
  }
  return buf;
}

bool byte_buf_set(byte_buf_t* buf, byte_t const data[], size_t len) {
  if (data == NULL || buf == NULL) {
    return false;
  }

  if (byte_buf_reserve(buf, len) == false) {
    return false;
  }

  memcpy(buf->data, data, len);
  buf->len = len;
  return true;
}

bool byte_buf_append(byte_buf_t* buf, byte_t const data[], size_t len) {
  if (data == NULL || buf == NULL) {
    return false;
  }
  // needed capacity
  size_t needed_cap = buf->len + len;

  if (byte_buf_reserve(buf, needed_cap) == false) {
    return false;
  }

  // copy data to buffer
  memcpy(buf->data + buf->len, data, len);
  buf->len += len;
  return true;
}

bool byte_buf_reserve(byte_buf_t* buf, size_t len) {
  if (!buf) {
    return false;
  }

  if (buf->cap >= len) {
    // capacity is bigger than the requested size.
    return true;
  }

  byte_t* new_buf = realloc(buf->data, len);
  if (new_buf == NULL) {
    return false;
  }
  buf->data = new_buf;
  buf->cap = len;
  return true;
}

void byte_buf_free(byte_buf_t* buf) {
  if (buf) {
    if (buf->data) {
      free(buf->data);
    }
    buf->len = 0;
    buf->cap = 0;
    free(buf);
  }
}

bool byte_buf2str(byte_buf_t* buf) {
  bool ret = true;
  byte_t null_char = '\0';
  if (buf && buf->data) {
    if (buf->data[buf->len - 1] != null_char) {
      ret = byte_buf_append(buf, &null_char, 1);
    }
  }
  return ret;
}

byte_buf_t* byte_buf_str2hex(byte_buf_t* buf) {
  byte_buf_t* hex_str = byte_buf_new();
  byte_buf_reserve(hex_str, (buf->len * 2) + 1);
  byte_buf2str(buf);
  if (string2hex((char*)buf->data, hex_str->data, hex_str->cap) != 0) {
    byte_buf_free(hex_str);
    return NULL;
  }

  // the data length includes string terminator
  hex_str->len = strlen((char*)hex_str->data) + 1;
  return hex_str;
}

byte_buf_t* byte_buf_hex2str(byte_buf_t* hex) {
  byte_buf_t* str = byte_buf_new();
  byte_buf2str(hex);
  byte_buf_reserve(str, (hex->len / 2) + 1);
  hex2string((char*)hex->data, str->data, str->cap);
  str->len = hex->len / 2;
  byte_buf2str(str);
  return str;
}

byte_buf_t* byte_buf_clonen(byte_buf_t* buf, size_t len) {
  byte_buf_t* clone = malloc(sizeof(byte_buf_t));
  if (!clone) {
    return NULL;
  }

  clone->len = len;
  clone->cap = len;
  clone->data = malloc(buf->len);
  if (!clone->data) {
    free(clone);
    return NULL;
  }

  memcpy(clone->data, buf->data, len);
  return clone;
}

void byte_buf_print(byte_buf_t* buf) {
  printf("byte_buf: cap = %zu, len = %zu\n", buf->cap, buf->len);
  dump_hex(buf->data, buf->len);
}
