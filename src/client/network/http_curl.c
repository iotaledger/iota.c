#ifndef __XTENSA__  // workaround: srcFilter is not working in PlatformIO
#include <curl/curl.h>

#include "client/network/http.h"

void http_client_clean() { curl_global_cleanup(); }

void http_client_init() { curl_global_init(CURL_GLOBAL_DEFAULT); }

static size_t cb_write_fn(void* data, size_t size, size_t nmemb, void* userp) {
  size_t realsize = size * nmemb;
  byte_buf_t* mem = (byte_buf_t*)userp;

  if (byte_buf_append(mem, data, realsize) == false) {
    // OOM or NULL data
    printf("append data failed\n");
  }
  return realsize;
}

int http_client_post(http_client_config_t const* const config, byte_buf_t const* const request,
                     byte_buf_t* const response) {
  int ret = 0;
  CURL* curl = curl_easy_init();
  struct curl_slist* headers = NULL;
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, config->url);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request->data);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_write_fn);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK) {
      printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      ret = -1;
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return ret;
  }
  return -1;
}

int http_client_get(http_client_config_t const* const config, byte_buf_t* const response) {
  int ret = 0;
  CURL* curl = curl_easy_init();
  struct curl_slist* headers = NULL;
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, config->url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");

    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_write_fn);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK) {
      printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
      ret = -1;
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return ret;
  }
  return -1;
}
#endif