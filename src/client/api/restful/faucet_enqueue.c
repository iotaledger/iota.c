// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/faucet_enqueue.h"
#include "client/network/http.h"

const char *const fauce_enqueue_api_path = "/api/plugins/faucet/v1/enqueue";

int deser_faucet_enqueue_response(char const *const j_str, res_req_faucet_tokens_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    printf("[%s:%d] NULL json object\n", __func__, __LINE__);
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    cJSON_Delete(json_obj);
    return 0;
  }

  // gets address
  if (json_get_string(json_obj, JSON_KEY_ADDR, res->u.req_res.bech32_address, sizeof(res->u.req_res.bech32_address)) !=
      0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_ADDR);
    cJSON_Delete(json_obj);
    return -1;
  }

  // get waiting requests count
  if (json_get_uint64(json_obj, JSON_KEY_WAITING_REQUESTS, &res->u.req_res.waiting_reqs_count) != 0) {
    printf("[%s:%d]: gets %s json integer failed\n", __func__, __LINE__, JSON_KEY_WAITING_REQUESTS);
    cJSON_Delete(json_obj);
    return -1;
  }
  cJSON_Delete(json_obj);
  return 0;
}

int req_tokens_to_addr_from_faucet(iota_client_conf_t const *conf, char const addr_bech32[],
                                   res_req_faucet_tokens_t *res) {
  // Check if any of input parameters are NULL
  if (conf == NULL || addr_bech32 == NULL || res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // Check if addr_bech32 has minimum requred length
  if (strlen(addr_bech32) < BECH32_ENCODED_ED25519_ADDRESS_STR_LEN) {
    printf("[%s:%d] invalid bech32 address\n", __func__, __LINE__);
    return -1;
  }

  // create post request body object
  cJSON *req_obj = cJSON_CreateObject();
  if (req_obj == NULL) {
    printf("[%s:%d] creating request object failed\n", __func__, __LINE__);
    return -1;
  }

  // Add address to request object
  if (!cJSON_AddStringToObject(req_obj, JSON_KEY_ADDR, addr_bech32)) {
    printf("[%s:%d] adding address to request object failed\n", __func__, __LINE__);
    cJSON_Delete(req_obj);
    return -1;
  }

  // json object to json string
  char *req_str = cJSON_PrintUnformatted(req_obj);
  if (req_str == NULL) {
    printf("[%s:%d] converting json to string failed\n", __func__, __LINE__);
    cJSON_Delete(req_obj);
    return -1;
  }
  // not needed anymore
  cJSON_Delete(req_obj);

  // put json string into byte_buf_t
  byte_buf_t *json_data = byte_buf_new_with_data((byte_t *)req_str, strlen(req_str) + 1);
  if (!json_data) {
    printf("[%s:%d] allocating buffer with request data failed\n", __func__, __LINE__);
    free(req_str);
    return -1;
  }
  // not needed anymore
  free(req_str);

  // config http client
  http_client_config_t http_conf = {
      .host = conf->host, .path = fauce_enqueue_api_path, .use_tls = conf->use_tls, .port = conf->port};

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d] allocating buffer for http response failed\n", __func__, __LINE__);
    byte_buf_free(json_data);
    return -1;
  }

  long http_st_code = 0;
  int ret = -1;
  if ((ret = http_client_post(&http_conf, json_data, http_res, &http_st_code)) == 0) {
    if (!byte_buf2str(http_res)) {
      byte_buf_free(json_data);
      byte_buf_free(http_res);
      printf("[%s:%d]: buffer to string conversion failed\n", __func__, __LINE__);
      return -1;
    }
    printf("Response : %s\n", http_res->data);
    ret = deser_faucet_enqueue_response((char const *)http_res->data, res);
  } else {
    printf("[%s:%d]: http client post failed\n", __func__, __LINE__);
    return -1;
  }
  byte_buf_free(json_data);
  byte_buf_free(http_res);
  return ret;
}
