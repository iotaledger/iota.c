// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.

#include "client/network/http.h"

#include <logging/log.h>
LOG_MODULE_REGISTER(iota_http, CONFIG_IOTA_HTTP_CLIENT_LOG_LEVEL);

#include <net/dns_resolve.h>
#include <net/http_client.h>
#include <net/net_ip.h>
#include <net/socket.h>
#include <net/socketutils.h>
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#include <net/tls_credentials.h>
#include "ca_certificate.h"
#endif

typedef struct {
  byte_buf_t* buf;
  uint16_t status_code;
} http_user_data_t;

static const char* http_headers[] = {"Content-Type: application/json\r\n", NULL};
static char recv_buff[CONFIG_IOTA_HTTP_RECV_BUFF_SIZE];
static char port_text[8];

static void response_cb(struct http_response* rsp, enum http_final_call final_data, void* user_data) {
  http_user_data_t* user = (http_user_data_t*)user_data;

  if (final_data == HTTP_DATA_MORE) {
    LOG_DBG("Partial data received (%d), processed (%d), content (%d)", rsp->data_len, rsp->processed,
            rsp->content_length);
    if (rsp->body_found) {
      if (rsp->body_start) {
        // header with response body
        byte_buf_append(user->buf, rsp->body_start, rsp->processed);
        LOG_DBG("buff append: %d", rsp->processed);
      } else {
        // response body
        byte_buf_append(user->buf, rsp->recv_buf, rsp->data_len);
        LOG_DBG("buff append: %d", rsp->data_len);
      }
    }
  } else if (final_data == HTTP_DATA_FINAL) {
    LOG_DBG("All the data received (%d bytes)", rsp->data_len);
    if (rsp->data_len) {
      byte_buf_append(user->buf, rsp->recv_buf, rsp->data_len);
      LOG_DBG("buff append: %d", rsp->data_len);
    }
  }

  user->status_code = rsp->http_status_code;
  LOG_DBG("Response status %s", rsp->http_status);
}

static int connect_socket(http_client_config_t const* const config) {
  struct addrinfo hints = {};
  struct addrinfo* addr = NULL;
  int st = 0, sock = 0;
  int ret = -1;

  LOG_DBG("socket connect to %s:%s, tls: %s\n", config->host, port_text, config->use_tls ? "true" : "false");
  if (config->use_tls) {
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    tls_credential_add(CA_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ca_certificate, sizeof(ca_certificate));
#else
    LOG_ERR("TLS socket is not enabled or supported");
    return -1;
#endif
  }

  // get address info from host
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  st = getaddrinfo(config->host, port_text, &hints, &addr);
  if (st != 0) {
    LOG_ERR("Unable to resolve address (%d)", -errno);
    return -errno;
  }

  if (config->use_tls) {
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    sec_tag_t sec_tag_opt[] = {
        CA_CERTIFICATE_TAG,
    };
    uint8_t peer_verify = TLS_PEER_VERIFY_OPTIONAL;
    sock = socket(addr->ai_family, addr->ai_socktype, IPPROTO_TLS_1_2);
    if (sock >= 0) {
      // select which credential to use with TLS
      ret = setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_opt, sizeof(sec_tag_opt));
      if (ret < 0) {
        LOG_ERR("Set TLS credentials failed (%d)", -errno);
        freeaddrinfo(addr);
        return -errno;
      }

      // set hostname
      ret = setsockopt(sock, SOL_TLS, TLS_HOSTNAME, config->host, strlen(config->host));
      if (ret < 0) {
        LOG_ERR("Set hostname verification failed (%d)", -errno);
        freeaddrinfo(addr);
        return -errno;
      }

      // mbedtsl auth mode
      ret = setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify, sizeof(peer_verify));
      if (ret < 0) {
        LOG_ERR("Set peer auth mode failed (%d)", -errno);
        freeaddrinfo(addr);
        return -errno;
      }
    }
#endif
  } else {
    sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  }

  if (sock < 0) {
    LOG_ERR("socket connect failed (%d)", -errno);
    freeaddrinfo(addr);
    return -errno;
  }

  ret = connect(sock, addr->ai_addr, addr->ai_addrlen);
  if (ret < 0) {
    LOG_ERR("Connect to %s:%d failed (%d)", config->host, config->port, -errno);
    freeaddrinfo(addr);
    return -errno;
  }
  freeaddrinfo(addr);
  return sock;
}

void http_client_clean() {}

void http_client_init() {}

int http_client_post(http_client_config_t const* const config, byte_buf_t const* const request,
                     byte_buf_t* const response, long* status) {
  int sock = -1;
  int ret = -1;
  int len = snprintf(port_text, sizeof(port_text), "%d", config->port);
  if (len > sizeof(port_text) - 1) {
    LOG_ERR("Invalid port number: %d", config->port);
    return -1;
  }

  sock = connect_socket(config);
  if (sock < 0) {
    return sock;
  }

  // http request
  struct http_request req = {};
  http_user_data_t user_data = {.buf = response, .status_code = 0};

  req.method = HTTP_POST;
  req.host = config->host;
  req.port = port_text;
  req.url = config->path;
  req.header_fields = http_headers;
  req.protocol = "HTTP/1.1";
  req.payload = request->data;
  req.payload_len = request->len;
  req.response = response_cb;
  req.recv_buf = recv_buff;
  req.recv_buf_len = sizeof(recv_buff);

  ret = http_client_req(sock, &req, 3 * MSEC_PER_SEC, &user_data);
  if (ret <= 0) {
    LOG_ERR("http sent request failed");
  } else {
    LOG_DBG("cap %d, len %d", response->cap, response->len);
  }
  *status = (long)user_data.status_code;

  close(sock);
  return 0;
}

int http_client_get(http_client_config_t const* const config, byte_buf_t* const response, long* status) {
  int sock = -1;
  int ret = -1;
  int len = snprintf(port_text, sizeof(port_text), "%d", config->port);
  if (len > sizeof(port_text) - 1) {
    LOG_ERR("Invalid port number: %d", config->port);
    return -1;
  }

  sock = connect_socket(config);
  if (sock < 0) {
    return sock;
  }

  // http request
  struct http_request req = {};
  http_user_data_t user_data = {.buf = response, .status_code = 0};

  req.method = HTTP_GET;
  req.host = config->host;
  req.port = port_text;
  req.url = config->path;
  req.header_fields = http_headers;
  req.protocol = "HTTP/1.1";
  req.response = response_cb;
  req.recv_buf = recv_buff;
  req.recv_buf_len = sizeof(recv_buff);

  ret = http_client_req(sock, &req, 3 * MSEC_PER_SEC, &user_data);
  if (ret <= 0) {
    LOG_ERR("http sent request failed");
  } else {
    LOG_DBG("cap %d, len %d", response->cap, response->len);
  }
  *status = (long)user_data.status_code;
  close(sock);
  return 0;
}
