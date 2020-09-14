#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

#include "network/http.h"
#include "unity/unity.h"

void test_http() {
  static char* str = "Hello!!";
  http_client_init();

  //=========HTTPS POST==========
  http_client_config_t conf = {0};
  http_buf_t* response = http_buf_new();
  http_buf_t* req = http_buf_new_with_data((byte_t*)str, strlen(str) + 1);
  conf.url = "https://postman-echo.com/post";
  http_client_post(response, &conf, req);
  http_buf2str(response);  // convert data to string for printf debugging.
  printf("%s\n", response->data);
  http_buf_free(response);
  http_buf_free(req);
  req = NULL;
  response = NULL;

  //=========HTTPS GET==========
  response = http_buf_new();
  conf.url = "https://example.com/";
  http_client_get(response, &conf);
  http_buf2str(response);  // convert data to string for printf debugging.
  printf("%s\n", response->data);
  http_buf_free(response);
  response = NULL;

  http_client_clean();
}

void test_restful() {
  http_client_init();
  http_client_config_t conf = {0};
  http_buf_t* response = http_buf_new();
  conf.url = "https://virtserver.swaggerhub.com/oopsmonk/mytest/0.0.1/messages/by-hash?hashes=thisisatesthash";
  http_client_get(response, &conf);
  // printf("%.*s\n", response->len, response->data);
  http_buf2str(response);  // convert data to string for printf debugging.
  printf("%s\n", response->data);
  http_buf_free(response);
  response = NULL;

  http_client_clean();
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_http);
  RUN_TEST(test_restful);

  return UNITY_END();
}