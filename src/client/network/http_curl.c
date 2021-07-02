// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __XTENSA__  // workaround: srcFilter is not working in PlatformIO
#include <curl/curl.h>

#include <stdio.h>
#include <string.h>

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

static char* prepare_url(http_client_config_t const* const config) {
  // calculate url length
  // https://host:port/path
  size_t len = 8 + strlen(config->host) + 8 + strlen(config->path);
  // allocate url buffer
  char* url = malloc(len * sizeof(char));
  if (!url) {
    printf("allocate buffer for url failed\n");
    return NULL;
  }
  // compose URL
  if (config->use_tls) {
    snprintf(url, len, "https://%s:%d%s", config->host, config->port, config->path);
  } else {
    snprintf(url, len, "http://%s:%d%s", config->host, config->port, config->path);
  }
  return url;
}

static void free_url(char* url) {
  // call
  if (url) {
    free(url);
  }
}

int http_client_post(http_client_config_t const* const config, byte_buf_t const* const request,
                     byte_buf_t* const response, long* status) {
  int ret = 0;
  CURL* curl = curl_easy_init();
  struct curl_slist* headers = NULL;
  char* url = NULL;
  if (curl) {
    if (!config->url) {
      url = prepare_url(config);
      curl_easy_setopt(curl, CURLOPT_URL, url);
    } else {
      curl_easy_setopt(curl, CURLOPT_URL, config->url);
    }

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

    // get http status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    /* always cleanup */
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free_url(url);
    return ret;
  }
  return -1;
}

int http_client_get(http_client_config_t const* const config, byte_buf_t* const response, long* status) {
  int ret = 0;
  CURL* curl = curl_easy_init();
  struct curl_slist* headers = NULL;
  char* url = NULL;

  if (curl) {
    if (!config->url) {
      url = prepare_url(config);
      curl_easy_setopt(curl, CURLOPT_URL, url);
    } else {
      curl_easy_setopt(curl, CURLOPT_URL, config->url);
    }
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

    // get http status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    /* always cleanup */
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free_url(url);
    return ret;
  }
  return -1;
}
#endif