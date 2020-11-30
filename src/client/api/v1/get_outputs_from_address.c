// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/v1/get_outputs_from_address.h"
#include "client/api/json_utils.h"

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

int get_outputs_from_address(iota_client_conf_t const *conf, char addr[], res_outputs_address_t *res) {
  // TODO
  return -1;
}