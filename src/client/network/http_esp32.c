#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_http_client.h"

#include "client/network/http.h"

#define HTTP_TIMEPUT_MS 30000  // timeout in ms
static const char* TAG = "HTTP_CLIENT";

static esp_err_t http_event_handler(esp_http_client_event_t* evt) {
  static uint64_t output_len;  // Stores number of bytes read
  http_buf_t* buf = (http_buf_t*)evt->user_data;

  switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
      ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
      break;
    case HTTP_EVENT_ON_CONNECTED:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
      break;
    case HTTP_EVENT_HEADER_SENT:
      ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
      break;
    case HTTP_EVENT_ON_HEADER:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
      break;
    case HTTP_EVENT_ON_DATA:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
      /*
       *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
       *  However, event handler can also be used in case chunked encoding is used.
       */
      if (!esp_http_client_is_chunked_response(evt->client)) {
        // If user_data buffer is configured, copy the response into the buffer
        if (buf) {
          http_buf_append(buf, evt->data, evt->data_len);
        } else {
          ESP_LOGE(TAG, "NULL buffer");
        }
        output_len += evt->data_len;
      }

      break;
    case HTTP_EVENT_ON_FINISH:
      ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
      output_len = 0;
      break;
    case HTTP_EVENT_DISCONNECTED:
      ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
      int mbedtls_err = 0;
      esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
      if (err != 0) {
        output_len = 0;
        ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
        ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
      }
      break;
  }
  return ESP_OK;
}

static void http_download_chunk(void) {
  esp_http_client_config_t config = {
      .url = "http://httpbin.org/stream-bytes/8912",
      .event_handler = http_event_handler,
  };
  esp_http_client_handle_t client = esp_http_client_init(&config);
  esp_err_t err = esp_http_client_perform(client);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "HTTP chunk encoding Status = %d, content_length = %d", esp_http_client_get_status_code(client),
             esp_http_client_get_content_length(client));
  } else {
    ESP_LOGE(TAG, "Error perform http request %s", esp_err_to_name(err));
  }
  esp_http_client_cleanup(client);
}

static void init_config(esp_http_client_config_t* esp, http_client_config_t const* const conf) {
  esp->url = conf->url;
  esp->host = conf->host;
  esp->path = conf->path;
  esp->query = conf->query;
  esp->username = conf->username;
  esp->password = conf->password;
  esp->port = conf->port;
  esp->cert_pem = conf->cert_pem;
  esp->timeout_ms = HTTP_TIMEPUT_MS;
  esp->event_handler = http_event_handler;
}

void http_client_init() {}

void http_client_clean() {}

void http_client_post(http_buf_t* const response, http_client_config_t const* const config,
                      http_buf_t const* const request) {
  // POST
  esp_http_client_config_t esp_client_conf = {0};
  init_config(&esp_client_conf, config);
  esp_client_conf.user_data = (void*)response;

  esp_http_client_handle_t client = esp_http_client_init(&esp_client_conf);
  esp_http_client_set_method(client, HTTP_METHOD_POST);
  esp_http_client_set_header(client, "Content-Type", "application/json");
  esp_http_client_set_post_field(client, (char const*)request->data, request->len);

  esp_err_t err = esp_http_client_perform(client);
  if (err == ESP_OK) {
    ESP_LOGI(TAG, "HTTP POST Status = %d, content_length = %d", esp_http_client_get_status_code(client),
             esp_http_client_get_content_length(client));
  } else {
    ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
  }
  esp_http_client_cleanup(client);
}

void http_client_get(http_buf_t* const response, http_client_config_t const* const config) {
  esp_http_client_config_t esp_client_conf = {0};
  init_config(&esp_client_conf, config);
  esp_client_conf.user_data = (void*)response;

  esp_http_client_handle_t client = esp_http_client_init(&esp_client_conf);

  esp_err_t err = esp_http_client_perform(client);
  if (err == ESP_OK) {
    ESP_LOGI(TAG, "HTTP GET Status = %d, content_length = %d", esp_http_client_get_status_code(client),
             esp_http_client_get_content_length(client));
  } else {
    ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
  }

  esp_http_client_cleanup(client);
}
