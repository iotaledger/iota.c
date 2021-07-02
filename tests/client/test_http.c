// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

#include "client/network/http.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_https_url() {
  static char* str = "Hello!!";
  http_client_init();

  //=========HTTPS POST==========
  http_client_config_t conf = {0};
  byte_buf_t* response = byte_buf_new();
  byte_buf_t* req = byte_buf_new_with_data((byte_t*)str, strlen(str) + 1);
  conf.url = "https://httpbin.org/post";
  long st = 0;
  TEST_ASSERT(http_client_post(&conf, req, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  // byte_buf2str(response);  // convert data to string for printf debugging.
  // printf("%s\n", response->data);
  byte_buf_free(response);
  byte_buf_free(req);
  req = NULL;
  response = NULL;

  //=========HTTPS GET==========
  response = byte_buf_new();
  conf.url = "https://httpbin.org/get";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  // byte_buf2str(response);  // convert data to string for printf debugging.
  // printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS Stream==========
  response = byte_buf_new();
  conf.url = "https://httpbin.org/stream-bytes/101";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  TEST_ASSERT_EQUAL_UINT32(101, response->len);
  // printf("%zu\n", response->len);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS base64 decode==========
  response = byte_buf_new();
  conf.url = "https://httpbin.org/base64/SFRUUEJJTiBpcyBhd2Vzb21l";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  byte_buf2str(response);  // convert data to string for strcmp.
  TEST_ASSERT_EQUAL_STRING("HTTPBIN is awesome", response->data);
  // printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS delay==========
  response = byte_buf_new();
  conf.url = "https://httpbin.org/delay/5";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  byte_buf2str(response);
  // printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS Stream JSON==========
  response = byte_buf_new();
  conf.url = "https://httpbin.org/stream/3";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  printf("data size: %zu\n", response->len);
  byte_buf2str(response);  // convert data to string for printf debugging.
  printf("string size: %zu\n", response->len);
  printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  http_client_clean();
}

void test_http_host_port() {
  static char* str = "Hello!!";
  char const* const hostname = "httpbin.org";
  http_client_init();

  //=========HTTPS POST==========
  http_client_config_t conf = {.host = hostname, .path = "/post", .port = 80, .use_tls = false};
  byte_buf_t* response = byte_buf_new();
  byte_buf_t* req = byte_buf_new_with_data((byte_t*)str, strlen(str) + 1);
  long st = 0;
  TEST_ASSERT(http_client_post(&conf, req, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  // byte_buf2str(response);  // convert data to string for printf debugging.
  // printf("%s\n", response->data);
  byte_buf_free(response);
  byte_buf_free(req);

  //=========HTTPS GET==========
  response = byte_buf_new();
  conf.path = "/get";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  // byte_buf2str(response);  // convert data to string for printf debugging.
  // printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS Stream==========
  response = byte_buf_new();
  conf.path = "/stream-bytes/101";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  TEST_ASSERT_EQUAL_UINT32(101, response->len);
  // printf("%zu\n", response->len);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS base64 decode==========
  response = byte_buf_new();
  conf.path = "/base64/SFRUUEJJTiBpcyBhd2Vzb21l";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  byte_buf2str(response);  // convert data to string for strcmp.
  TEST_ASSERT_EQUAL_STRING("HTTPBIN is awesome", response->data);
  // printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS delay==========
  response = byte_buf_new();
  conf.path = "/delay/5";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  byte_buf2str(response);
  // printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  //=========HTTPS Stream JSON==========
  response = byte_buf_new();
  conf.path = "/stream/3";
  TEST_ASSERT(http_client_get(&conf, response, &st) == 0);
  TEST_ASSERT(st == 200);
  TEST_ASSERT_NOT_NULL(response->data);
  printf("data size: %zu\n", response->len);
  byte_buf2str(response);  // convert data to string for printf debugging.
  printf("string size: %zu\n", response->len);
  printf("%s\n", response->data);
  byte_buf_free(response);
  response = NULL;

  http_client_clean();
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_https_url);
  RUN_TEST(test_http_host_port);

  return UNITY_END();
}