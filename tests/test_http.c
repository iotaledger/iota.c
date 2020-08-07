#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

#include "network/http.h"
#include "unity/unity.h"

void test_http() {
  static char* str = "Hello!!";
  http_client_init();

  http_buf_t* response = http_buf_new();
  http_buf_t* req = http_buf_new_with_data(str, strlen(str) + 1);
  http_client_post(response, "https://postman-echo.com/post", req);
  printf("%s\n", response->data);
  http_buf_free(response);
  http_buf_free(req);
  req = NULL;
  response = NULL;

  response = http_buf_new();
  http_client_get(response, "https://example.com/");
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