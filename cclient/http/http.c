/*
 * Copyright (c) 2018 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

#include <string.h>

#include "cclient/http/socket.h"
#include "cclient/service.h"
#include "http.h"
#include "http_parser.h"

/**
 * @brief http payload buffer
 *
 */
typedef struct {
  char* data; /*!< The HTTP data received from the server */
  int len;    /*!< The HTTP data len received from the server */
  int cap;    /*!< The Buffer capacity */
} http_buffer_t;

/**
 * @brief http request/response object
 *
 */
typedef struct {
  http_buffer_t* buffer;    /*!< data buffer as linked list */
  uint64_t content_length;  /*!< data length */
  uint32_t data_offset;     /*!< offset to http data (Skip header) */
  unsigned int method;      /*!< request method POST/GET/PUT... */
  unsigned int status_code; /*!< status code (integer) */
  uint64_t data_process;    /*!< data processed */
  bool is_chunked;          /*!< chunked transfer */
} http_data_t;

/**
 * @brief http connection status
 *
 */
typedef enum {
  HTTP_STATE_UNINIT = 0,
  HTTP_STATE_INIT,
  HTTP_STATE_CONNECTED,
  HTTP_STATE_REQ_COMPLETE_HEADER,
  HTTP_STATE_REQ_COMPLETE_DATA,
  HTTP_STATE_RES_COMPLETE_HEADER,
  HTTP_STATE_RES_COMPLETE_DATA,
  HTTP_STATE_CLOSE,
  HTTP_STATE_OOM
} http_state_t;

/**
 * @brief http client object
 *
 */
typedef struct {
  http_info_t const* http_config;
  struct http_parser* parser;
  struct http_parser_settings* parser_settings;
  mbedtls_ctx_t* tls;
  http_data_t* request;
  http_data_t* response;
  http_buffer_t* res_data;
  uint64_t buffer_size_rx;
  uint64_t buffer_size_tx;
  http_state_t state;
  bool is_chunk_completed;
} http_client_ctx_t;

char const* khttp_ApplicationJson = "application/json";
char const* khttp_ApplicationFormUrlencoded = "application/x-www-form-urlencoded";

static char const* header_template =
    "POST %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "X-IOTA-API-Version: %d\r\n"
    "Content-Type: %s\r\n"
    "User-Agent: IOTA CClient\r\n"
    "Accept: %s\r\n"
    "Content-Length: %lu\r\n"
    "\r\n";

/**
 * @brief debug method
 *
 */
static void parser_print_data(char const* at, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%c", *(at + i));
  }
  printf("\n");
}

/**
 * @brief new a http buffer
 *
 * @param len initial buffer size
 * @return http_buffer_t*
 */
static http_buffer_t* http_buffer_new(int len) {
  http_buffer_t* buf = calloc(1, sizeof(http_buffer_t));
  if (buf) {
    if ((buf->data = malloc(len)) == NULL) {
      free(buf);
      return NULL;
    }
    buf->cap = len;
    buf->len = 0;
    return buf;
  }
  return NULL;
}

/**
 * @brief cleanup http buffer
 *
 * @param buf a http_buffer_t object
 */
static void http_buffer_free(http_buffer_t** buf) {
  if (buf != NULL && (*buf) != NULL) {
    if ((*buf)->data) {
      free((*buf)->data);
    }
    free(*buf);
    *buf = NULL;
  }
}

/**
 * @brief writes data at begining, realloc if len bigger than capacity.
 *
 * @param buf a http buffer object
 * @param data a pointer to data
 * @param len data size
 * @return int
 */
static int http_buffer_set(http_buffer_t* buf, char* data, int len) {
  if (buf->cap < len) {
    buf->cap = len;
    if ((buf->data = (char*)realloc(buf->data, buf->cap)) == NULL) {
      return -1;
    }
  }
  memcpy(buf->data, data, len);
  buf->len = len;
  return len;
}

/**
 * @brief writes data at the end of data, realloc if total data length bigger than capacity.
 *
 * @param buf a http buffer object
 * @param data a pointer to data
 * @param len data size
 * @return int
 */
static int http_buffer_append(http_buffer_t* buf, char const* data, int len) {
  int required_len = buf->len + len;
  if (buf->cap < required_len) {
    // need to allocate a larger buffer
    buf->cap = buf->len + (len * 2);
    if ((buf->data = (char*)realloc(buf->data, buf->cap)) == NULL) {
      printf("[%s:%d] realloc failed\n", __func__, __LINE__);
      return -1;
    }
  }

  // copy new data to buffer
  memcpy(buf->data + buf->len, data, len);
  buf->len = required_len;
  return buf->len;
}

static int parser_on_message_begin(http_parser* parser) {
  http_client_ctx_t* client = parser->data;
  client->response->is_chunked = false;
  client->is_chunk_completed = false;
  return 0;
}

static int parser_on_url(http_parser* parser, char const* at, size_t length) {
  (void)parser;
  (void)at;
  (void)length;
  // parser_print_data(at, length);
  return 0;
}

static int parser_on_status(http_parser* parser, char const* at, size_t length) {
  (void)parser;
  (void)at;
  (void)length;
  // parser_print_data(at, length);
  return 0;
}

static int parser_on_header_field(http_parser* parser, char const* at, size_t length) {
  (void)parser;
  (void)at;
  (void)length;
  // parser_print_data(at, length);

  return 0;
}

static int parser_on_header_value(http_parser* parser, char const* at, size_t length) {
  (void)parser;
  (void)at;
  (void)length;
  // parser_print_data(at, length);

  return 0;
}

static int parser_on_headers_complete(http_parser* parser) {
  http_client_ctx_t* client = parser->data;
  client->response->status_code = parser->status_code;
  client->response->data_offset = parser->nread;
  client->response->content_length = parser->content_length;
  client->response->data_process = 0;
  client->state = HTTP_STATE_RES_COMPLETE_HEADER;

  if (parser->content_length != UINT64_MAX) {
    // no content_length in header
    if ((client->res_data = http_buffer_new(parser->content_length)) == NULL) {
      client->state = HTTP_STATE_OOM;
      return -1;
    }

  } else {
    client->response->is_chunked = true;
  }

  // for debugging, remove later
  if (parser->status_code != 200) {
    printf("[%s:%d] status=%d, offset=%d, nread=%d\n", __func__, __LINE__, parser->status_code,
           client->response->data_offset, parser->nread);
  }
  return 0;
}

static int parser_on_body(http_parser* parser, char const* at, size_t length) {
  // parser_print_data(at, length);

  http_client_ctx_t* client = parser->data;
  int res_len = http_buffer_append(client->res_data, at, length);
  if (res_len < 0) {
    printf("[%s:%d] put data to buffer failed\n", __func__, __LINE__);
    return -1;
  }
  // memcpy(client->response->buffer->data, at, length);
  client->response->data_process += length;

  return 0;
}

static int parser_on_message_complete(http_parser* parser) {
  (void)parser;
  // printf("[%s:%d] \n", __func__, __LINE__);
  return 0;
}

static int parser_on_chunk_header(http_parser* parser) {
  // (void)parser;
  // printf("[%s:%d] \n", __func__, __LINE__);
  http_client_ctx_t* client = parser->data;
  client->response->is_chunked = true;

  // there is no content_length in chunked transfer
  if ((client->res_data = http_buffer_new(CCLIENT_HTTP_BUFFER_SIZE)) == NULL) {
    client->state = HTTP_STATE_OOM;
    return -1;
  }
  return 0;
}

static int parser_on_chunk_complete(http_parser* parser) {
  // (void)parser;
  // printf("[%s:%d] \n", __func__, __LINE__);
  http_client_ctx_t* client = parser->data;
  client->is_chunk_completed = true;
  return 0;
}

static void http_client_free(http_client_ctx_t* client_ctx) {
  if (client_ctx) {
    mbedtls_socket_close(client_ctx->tls);
    free(client_ctx->tls);
    http_buffer_free(&client_ctx->request->buffer);
    free(client_ctx->request);
    http_buffer_free(&client_ctx->response->buffer);
    free(client_ctx->response);
    http_buffer_free(&client_ctx->res_data);
    free(client_ctx->parser);
    free(client_ctx->parser_settings);
    free(client_ctx);
  }
}

static http_client_ctx_t* http_client_init(void const* const service_opaque) {
  iota_client_service_t const* const service = (iota_client_service_t const* const)service_opaque;
  http_client_ctx_t* client = NULL;
  bool init =
      ((client = calloc(1, sizeof(http_client_ctx_t))) && (client->parser = calloc(1, sizeof(struct http_parser))) &&
       (client->parser_settings = calloc(1, sizeof(struct http_parser_settings))) &&
       (client->tls = malloc(sizeof(mbedtls_ctx_t))) && (client->request = calloc(1, sizeof(http_data_t))) &&
       (client->response = calloc(1, sizeof(http_data_t))));

  if (!init) {
    printf("OOM\n");
    goto error;
  }
  client->http_config = &service->http;
  // TODO: configure by methods
  client->buffer_size_rx = CCLIENT_HTTP_BUFFER_SIZE;
  client->buffer_size_tx = CCLIENT_HTTP_BUFFER_SIZE;

  init = ((client->request->buffer = http_buffer_new(client->buffer_size_tx)) &&
          (client->response->buffer = http_buffer_new(client->buffer_size_rx)));

  if (!init) {
    printf("HTTP buffer Allocation failed\n");
    goto error;
  }

  client->parser_settings->on_message_begin = parser_on_message_begin;
  client->parser_settings->on_url = parser_on_url;
  client->parser_settings->on_status = parser_on_status;
  client->parser_settings->on_header_field = parser_on_header_field;
  client->parser_settings->on_header_value = parser_on_header_value;
  client->parser_settings->on_headers_complete = parser_on_headers_complete;
  client->parser_settings->on_body = parser_on_body;
  client->parser_settings->on_message_complete = parser_on_message_complete;
  client->parser_settings->on_chunk_header = parser_on_chunk_header;
  client->parser_settings->on_chunk_complete = parser_on_chunk_complete;
  http_parser_init(client->parser, HTTP_RESPONSE);
  client->parser->data = client;

  client->state = HTTP_STATE_INIT;
  return client;
error:
  http_client_free(client);
  return NULL;
}

static int http_client_send_req_header(http_client_ctx_t* client, int data_len) {
  sprintf(client->request->buffer->data, header_template, client->http_config->path, client->http_config->host,
          client->http_config->api_version, client->http_config->content_type, client->http_config->accept, data_len);
  client->request->buffer->len = strlen(client->request->buffer->data);
  int wlen = mbedtls_socket_send(client->tls, client->request->buffer->data, client->request->buffer->len);
  client->state = HTTP_STATE_REQ_COMPLETE_HEADER;
  return wlen;
}

static retcode_t http_client_send_req_data(http_client_ctx_t* client, char* data, int data_len) {
  char* ptr = (char*)data;
  while (data_len > 0) {
    int num_sent = mbedtls_socket_send(client->tls, ptr, data_len);
    if (num_sent < 0) {
      return RC_UTILS_SOCKET_SEND;
    }
    ptr += num_sent;
    data_len -= num_sent;
  }
  client->state = HTTP_STATE_REQ_COMPLETE_DATA;
  return RC_OK;
}

static int http_client_fetch_res_header(http_client_ctx_t* client) {
  if (client->state < HTTP_STATE_REQ_COMPLETE_HEADER) {
    printf("client->state < HTTP_STATE_REQ_COMPLETE_HEADER\n");
    return -1;
  }
  http_buffer_t* buffer = client->response->buffer;
  client->state = HTTP_STATE_REQ_COMPLETE_DATA;
  client->response->status_code = -1;

  while (client->state < HTTP_STATE_RES_COMPLETE_HEADER) {
    buffer->len = mbedtls_socket_recv(client->tls, buffer->data, client->buffer_size_rx);
    if (buffer->len <= 0) {
      // printf("buffer->len <= 0\n");
      return -1;
    }
    http_parser_execute(client->parser, client->parser_settings, buffer->data, buffer->len);
  }

  if (client->response->is_chunked) {
    // printf("[%s:%d] chunked transfer\n", __func__, __LINE__);
    return 0;
  }
  return client->response->content_length;
}

static int http_client_fetch_res_data(http_client_ctx_t* client) {
  if (client->state < HTTP_STATE_RES_COMPLETE_HEADER) {
    return -1;
  }

  http_buffer_t* res_buffer = client->response->buffer;
  int r_len = mbedtls_socket_recv(client->tls, res_buffer->data, client->buffer_size_rx);
  if (r_len >= 0) {
    http_parser_execute(client->parser, client->parser_settings, res_buffer->data, r_len);
  }
  return r_len;
}

static retcode_t cclient_socket_send(void const* const service_opaque, char_buffer_t const* const req_data,
                                     char_buffer_t* const res_data) {
  retcode_t result = RC_ERROR;
  // init http client instance
  http_client_ctx_t* http_client = http_client_init(service_opaque);
  if (!http_client) {
    printf("[%s:%d] Init http client failed\n", __func__, __LINE__);
    return RC_OOM;
  }

  switch (http_client->state) {
    case HTTP_STATE_INIT:
      // connect to socket
      if (mbedtls_socket_connect(http_client->tls, http_client->http_config->host, http_client->http_config->port,
                                 http_client->http_config->ca_pem, NULL, NULL, &result) < 0) {
        goto err;
      }
    // falls through
    case HTTP_STATE_CONNECTED:
      // send request header
      if (http_client_send_req_header(http_client, req_data->length) < 0) {
        printf("[%s:%d] send request header error\n", __func__, __LINE__);
        goto err;
      }

    // falls through
    case HTTP_STATE_REQ_COMPLETE_HEADER:
      // send request data
      if (http_client_send_req_data(http_client, req_data->data, req_data->length) != RC_OK) {
        printf("[%s:%d] send request data error\n", __func__, __LINE__);
        goto err;
      }

    // falls through
    case HTTP_STATE_REQ_COMPLETE_DATA:
      // handle response header
      if (http_client_fetch_res_header(http_client) < 0) {
        printf("[%s:%d] fetch response header error\n", __func__, __LINE__);
        result = RC_UTILS_SOCKET_RECV;
        goto err;
      }

    // falls through
    case HTTP_STATE_RES_COMPLETE_HEADER:
      // TODO: check response data
      if (http_client->response->status_code == 500) {
        goto err;
      } else if (http_client->response->status_code == 301 || http_client->response->status_code == 401) {
        printf("TODO: unsupported http request\n");
      }

      while (http_client->response->is_chunked && !http_client->is_chunk_completed) {
        // handle chunked transfer
        if (http_client_fetch_res_data(http_client) <= 0) {
          printf("Read finish or server requests close");
          break;
        }
      }

      while (http_client->response->data_process < http_client->response->content_length &&
             !http_client->response->is_chunked) {
        if (http_client_fetch_res_data(http_client) <= 0) {
          printf("Read finish or server requests close");
          break;
        }
      }

      break;
    case HTTP_STATE_OOM:
      goto err;
      break;
    default:
      break;
  }

  // TODO: refactor
  // copy res_data to res_data
  if (char_buffer_allocate(res_data, http_client->res_data->len) != RC_OK) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    goto err;
  }
  memcpy(res_data->data, http_client->res_data->data, http_client->res_data->len);
  result = RC_OK;

err:
  http_client_free(http_client);
  return result;
}

retcode_t iota_service_query(void const* const service_opaque, char_buffer_t const* const req_data,
                             char_buffer_t* res_data) {
  if (!service_opaque || !req_data || !res_data) {
    return RC_NULL_PARAM;
  }

  retcode_t ret = cclient_socket_send(service_opaque, req_data, res_data);
  size_t retry = 0;
  while (ret == RC_UTILS_SOCKET_RECV || ret == RC_UTILS_SOCKET_SEND) {
    if (retry > CCLIENT_SOCKET_RETRY) {
      break;
    }
    ret = cclient_socket_send(service_opaque, req_data, res_data);
    retry++;
  }
  return ret;
}
