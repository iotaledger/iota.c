#include <string.h>

#include "client/network/http_buffer.h"
#include "core/utils/allocator.h"

http_buf_t* http_buf_new() {
  http_buf_t* buf = malloc(sizeof(http_buf_t));
  if (buf) {
    buf->data = NULL;
    buf->len = 0;
  }
  return buf;
}

http_buf_t* http_buf_new_with_data(byte_t data[], size_t len) {
  if (data == NULL) {
    return NULL;
  }

  http_buf_t* buf = malloc(sizeof(http_buf_t));
  if (buf) {
    buf->data = malloc(len);
    if (buf->data) {
      memcpy(buf->data, data, len);
      buf->len = len;
    } else {
      // Out of Memory
      free(buf);
      return NULL;
    }
  }
  return buf;
}

bool http_buf_append(http_buf_t* buf, byte_t data[], size_t len) {
  if (data == NULL || buf == NULL) {
    return false;
  }

  if (buf->data == NULL) {
    buf->data = malloc(len);
    buf->len = 0;
  } else {
    buf->data = realloc(buf->data, buf->len + len);
  }

  if (buf->data == NULL) {
    // Out of memory
    return false;
  }

  memcpy(&(buf->data[buf->len]), data, len);
  buf->len += len;
  return true;
}

void http_buf_free(http_buf_t* buf) {
  if (buf) {
    if (buf->data) {
      free(buf->data);
    }
    buf->len = 0;
    free(buf);
  }
}

void http_buf2str(http_buf_t* buf) {
  if (buf && buf->data) {
    if (buf->data[buf->len - 1] != '\0') {
      buf->data = realloc(buf->data, buf->len + 1);
      buf->data[buf->len] = '\0';
      buf->len += 1;
    }
  }
}