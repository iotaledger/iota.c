#include <string.h>

#include "core/utils/allocator.h"
#include "core/utils/byte_buffer.h"

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

void byte_buf2str(byte_buf_t* buf) {
  byte_t null_char = '\0';
  if (buf && buf->data) {
    if (buf->data[buf->len - 1] != null_char) {
      byte_buf_append(buf, &null_char, 1);
    }
  }
}

byte_buf_t* byte_buf2hex_string(byte_buf_t* buf) {
  char const* hex_table = "0123456789ABCDEF";
  byte_buf_t* hex_str = byte_buf_new();
  byte_buf_reserve(hex_str, (buf->len * 2) + 1);
  for (size_t i = 0; i < buf->len; i++) {
    hex_str->data[i * 2 + 0] = hex_table[(buf->data[i] >> 4) & 0x0F];
    hex_str->data[i * 2 + 1] = hex_table[(buf->data[i]) & 0x0F];
    hex_str->len += 2;
  }
  hex_str->data[hex_str->len] = '\0';
  return hex_str;
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
