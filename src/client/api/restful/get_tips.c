// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_tips.h"
#include "core/utils/iota_str.h"

res_tips_t *res_tips_new() {
  res_tips_t *tips = malloc(sizeof(res_tips_t));
  if (tips) {
    tips->u.tips = NULL;
    tips->is_error = false;
    return tips;
  }
  return NULL;
}

void res_tips_free(res_tips_t *tips) {
  if (tips) {
    if (tips->is_error) {
      res_err_free(tips->u.error);
    } else {
      if (tips->u.tips) {
        utarray_free(tips->u.tips);
      }
    }
    free(tips);
  }
}

int get_tips(iota_client_conf_t const *conf, res_tips_t *res) {
  if (conf == NULL || res == NULL) {
    printf("[%s:%d]: Invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  // http client configuration
  http_client_config_t http_conf = {
      .host = conf->host, .path = "/api/v2/tips", .use_tls = conf->use_tls, .port = conf->port};

  byte_buf_t *http_res = byte_buf_new();
  if (!http_res) {
    printf("[%s:%d]: allocate response failed\n", __func__, __LINE__);
    return -1;
  }

  // send request via http client
  long status = 0;
  if (http_client_get(&http_conf, http_res, &status) != 0) {
    printf("[%s:%d] network error\n", __func__, __LINE__);
    byte_buf_free(http_res);
    return -1;
  }

  // convert response byte buffer into a string
  if (byte_buf2str(http_res) != true) {
    printf("[%s:%d]: byte buffer to string conversion failed\n", __func__, __LINE__);
    byte_buf_free(http_res);
    return -1;
  }

  // json deserialization
  int ret = get_tips_deserialize((char const *const)http_res->data, res);
  byte_buf_free(http_res);

  return ret;
}

int get_tips_deserialize(char const *const j_str, res_tips_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  cJSON *json_obj = cJSON_Parse(j_str);
  if (!json_obj) {
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

  utarray_new(res->u.tips, &ut_str_icd);
  int ret = json_string_with_prefix_array_to_utarray(json_obj, JSON_KEY_TIP_MSG_IDS, res->u.tips);
  if (ret != 0) {
    printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_TIP_MSG_IDS);
    utarray_free(res->u.tips);
    res->u.tips = NULL;
  }

  cJSON_Delete(json_obj);
  return ret;
}

size_t get_tips_id_count(res_tips_t *tips) {
  if (tips) {
    if (!tips->is_error && tips->u.tips) {
      return utarray_len(tips->u.tips);
    }
  }
  return 0;
}

char *get_tips_id(res_tips_t *tips, size_t index) {
  if (tips) {
    if (!tips->is_error && tips->u.tips) {
      return *(char **)utarray_eltptr(tips->u.tips, index);
    }
  }
  return NULL;
}
