#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

#include "client/network/http.h"
#include "unity/unity.h"

void test_http() {
  static char* str = "Hello!!";
  http_client_init();

  //=========HTTPS POST==========
  http_client_config_t conf = {0};
  http_buf_t* response = http_buf_new();
  http_buf_t* req = http_buf_new_with_data((byte_t*)str, strlen(str) + 1);
  conf.url = "https://httpbin.org/post";
  http_client_post(response, &conf, req);
  TEST_ASSERT_NOT_NULL(response->data);
  // http_buf2str(response);  // convert data to string for printf debugging.
  // printf("%s\n", response->data);
  http_buf_free(response);
  http_buf_free(req);
  req = NULL;
  response = NULL;

  //=========HTTPS GET==========
  response = http_buf_new();
  conf.url = "https://httpbin.org/get";
  http_client_get(response, &conf);
  TEST_ASSERT_NOT_NULL(response->data);
  // http_buf2str(response);  // convert data to string for printf debugging.
  // printf("%s\n", response->data);
  http_buf_free(response);
  response = NULL;

  //=========HTTPS Stream==========
  response = http_buf_new();
  conf.url = "https://httpbin.org/stream-bytes/101";
  http_client_get(response, &conf);
  TEST_ASSERT_NOT_NULL(response->data);
  TEST_ASSERT_EQUAL_UINT32(101, response->len);
  // printf("%zu\n", response->len);
  http_buf_free(response);
  response = NULL;

  //=========HTTPS base64 decode==========
  response = http_buf_new();
  conf.url = "https://httpbin.org/base64/SFRUUEJJTiBpcyBhd2Vzb21l";
  http_client_get(response, &conf);
  TEST_ASSERT_NOT_NULL(response->data);
  http_buf2str(response);  // convert data to string for strcmp.
  TEST_ASSERT_EQUAL_STRING("HTTPBIN is awesome", response->data);
  // printf("%s\n", response->data);
  http_buf_free(response);
  response = NULL;

  //=========HTTPS delay==========
  response = http_buf_new();
  conf.url = "https://httpbin.org/delay/5";
  http_client_get(response, &conf);
  TEST_ASSERT_NOT_NULL(response->data);
  http_buf2str(response);
  printf("%s\n", response->data);
  http_buf_free(response);
  response = NULL;

  //=========HTTPS Stream JSON==========
  response = http_buf_new();
  conf.url = "https://httpbin.org/stream/3";
  http_client_get(response, &conf);
  TEST_ASSERT_NOT_NULL(response->data);
  printf("data size: %zu\n", response->len);
  http_buf2str(response);  // convert data to string for printf debugging.
  printf("string size: %zu\n", response->len);
  printf("%s\n", response->data);
  http_buf_free(response);
  response = NULL;

  http_client_clean();
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_http);

  return UNITY_END();
}