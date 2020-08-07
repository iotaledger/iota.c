#include <curl/curl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"

void http_client_clean() { curl_global_cleanup(); }

void http_client_init() { curl_global_init(CURL_GLOBAL_DEFAULT); }

static size_t cb_write_fn(void* data, size_t size, size_t nmemb, void* userp) {
  size_t realsize = size * nmemb;
  http_buf_t* mem = (http_buf_t*)userp;

  if (http_buf_append(mem, data, realsize) == false) {
    // OOM or NULL data
    printf("append data failed\n");
  }
  return realsize;
}

void http_client_post(http_buf_t* const response, char const* const url, http_buf_t const* const request) {
  CURL* curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    // curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request->data);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_write_fn);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK) fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}

void http_client_get(http_buf_t* const response, char const* const url) {
  CURL* curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_write_fn);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);

    CURLcode res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK) fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}