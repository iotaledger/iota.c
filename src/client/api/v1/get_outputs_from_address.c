// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/v1/get_outputs_from_address.h"
#include "client/api/json_utils.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

static get_outputs_address_t *outputs_new() {
  get_outputs_address_t *ids = malloc(sizeof(get_outputs_address_t));
  memset(ids->address, 0, sizeof(ids->address));
  ids->count = 0;
  ids->max_results = 0;
  utarray_new(ids->outputs, &ut_str_icd);
  return ids;
}

static void outputs_free(get_outputs_address_t *ids) {
  if (ids->outputs) {
    utarray_free(ids->outputs);
  }
  free(ids);
}

res_outputs_address_t *res_outputs_address_new() {
  res_outputs_address_t *res = malloc(sizeof(res_outputs_address_t));
  res->is_error = false;
  return res;
}

void res_outputs_address_free(res_outputs_address_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      outputs_free(res->u.output_ids);
    }
    free(res);
  }
}

char *res_outputs_address_output_id(res_outputs_address_t *res, size_t index) {
  if (res == NULL) {
    return NULL;
  }

  if (utarray_len(res->u.output_ids->outputs)) {
    char **p = (char **)utarray_eltptr(res->u.output_ids->outputs, index);
    return *p;
  }
  return NULL;
}

size_t res_outputs_address_output_id_count(res_outputs_address_t *res) {
  if (res == NULL) {
    return 0;
  }
  return utarray_len(res->u.output_ids->outputs);
}
int deser_outputs_from_address(char const *const j_str, res_outputs_address_t *res) {
  char const *const key_address = "address";
  char const *const key_result = "maxResults";
  char const *const key_count = "count";
  char const *const key_outputs = "outputIds";

  int ret = 0;
  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  res_err_t *res_err = deser_error(json_obj);
  if (res_err) {
    // got an error response
    res->is_error = true;
    res->u.error = res_err;
    goto end;
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    res->u.output_ids = outputs_new();
    if (res->u.output_ids == NULL) {
      // OOM
      ret = -1;
      goto end;
    }

    if ((ret = json_get_string(data_obj, key_address, res->u.output_ids->address,
                               sizeof(res->u.output_ids->address))) != 0) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, key_address);
      ret = -1;
      goto end;
    }

    if ((ret = json_get_uint32(data_obj, key_result, &res->u.output_ids->max_results) != 0)) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, key_result);
      ret = -1;
      goto end;
    }

    if ((ret = json_get_uint32(data_obj, key_count, &res->u.output_ids->count) != 0)) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, key_count);
      ret = -1;
      goto end;
    }

    if ((ret = json_string_array_to_utarray(data_obj, key_outputs, res->u.output_ids->outputs)) != 0) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, key_outputs);
      ret = -1;
      goto end;
    }

  } else {
    // JSON format mismatched.
    ret = -1;
  }

end:
  cJSON_Delete(json_obj);

  return ret;
}

int get_outputs_from_address(iota_client_conf_t const *conf, char const addr[], res_outputs_address_t *res) {
  int ret = 0;
  if (conf == NULL || addr == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }

  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);
  if (cmd == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  char cmd_buf[100] = {};
  sprintf(cmd_buf, "api/v1/addresses/%s/outputs", addr);
  if (iota_str_append(cmd, cmd_buf)) {
    printf("[%s:%d]: cmd append failed\n", __func__, __LINE__);
    return -1;
  }

  // http client configuration
  http_client_config_t http_conf = {0};
  http_conf.url = cmd->buf;
  if (conf->port) {
    http_conf.port = conf->port;
  }

  byte_buf_t *http_res = byte_buf_new();
  if (http_res == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    ret = -1;
    goto done;
  }

  // send request via http client
  long st = 0;
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_outputs_from_address((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}
