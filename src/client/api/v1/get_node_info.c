// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_node_info.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

res_node_info_t *res_node_info_new() {
  res_node_info_t *res = malloc(sizeof(res_node_info_t));
  if (res == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return NULL;
  }
  res->is_error = false;
  res->u.output_node_info = NULL;
  return res;
}

void res_node_info_free(res_node_info_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.output_node_info) {
        if (res->u.output_node_info->features) {
          utarray_free(res->u.output_node_info->features);
        }
        free(res->u.output_node_info);
      }
    }
    free(res);
  }
}

char *get_node_features_at(res_node_info_t *info, size_t idx) {
  if (info == NULL) {
    printf("[%s:%d]: get_features failed (null parameter)\n", __func__, __LINE__);
    return NULL;
  }

  int len = utarray_len(info->u.output_node_info->features);
  if (idx >= len) {
    printf("[%s:%d]: get_features failed (invalid index)\n", __func__, __LINE__);
    return NULL;
  }

  return *(char **)utarray_eltptr(info->u.output_node_info->features, idx);
}

size_t get_node_features_num(res_node_info_t *info) {
  if (info == NULL) {
    printf("[%s:%d]: get_features failed (null parameter)\n", __func__, __LINE__);
    return 0;
  }

  return utarray_len(info->u.output_node_info->features);
}

int get_node_info(iota_client_conf_t const *conf, res_node_info_t *res) {
  int ret = 0;
  char const *const cmd_info = "/api/v1/info";
  if (conf == NULL || res == NULL) {
    printf("[%s:%d]: get_node_info failed (null parameter)\n", __func__, __LINE__);
    return -1;
  }

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd_info, .use_tls = conf->use_tls, .port = conf->port};

  byte_buf_t *http_res = byte_buf_new();
  if (http_res == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    ret = -1;
    goto done;
  }

  // send request via http client
  long st = 0;
  int http_ret = http_client_get(&http_conf, http_res, &st);
  if (http_ret != 0 || http_res->len == 0) {
    // request failed or no response data
    ret = -1;
    goto done;
  }

  byte_buf2str(http_res);

  // json deserialization
  ret = deser_node_info((char const *const)http_res->data, res);

done:
  byte_buf_free(http_res);

  return ret;
}

int deser_node_info(char const *const j_str, res_node_info_t *res) {
  int ret = 0;
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
    ret = 0;
    goto end;
  }

  res->u.output_node_info = malloc(sizeof(get_node_info_t));
  if (res->u.output_node_info == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    ret = -1;
    goto end;
  }
  memset(res->u.output_node_info, 0, sizeof(get_node_info_t));

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_DATA);
  if (data_obj) {
    // gets name
    if ((ret = json_get_string(data_obj, JSON_KEY_NAME, res->u.output_node_info->name,
                               sizeof(res->u.output_node_info->name))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NAME);
      goto end;
    }

    // gets version
    if ((ret = json_get_string(data_obj, JSON_KEY_VER, res->u.output_node_info->version,
                               sizeof(res->u.output_node_info->version))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_VER);
      goto end;
    }

    // gets isHealthy
    if ((ret = json_get_boolean(data_obj, JSON_KEY_IS_HEALTHY, &res->u.output_node_info->is_healthy)) != 0) {
      printf("[%s:%d]: gets %s json boolean failed\n", __func__, __LINE__, JSON_KEY_IS_HEALTHY);
      goto end;
    }

    // gets networkId
    if ((ret = json_get_string(data_obj, JSON_KEY_NET_ID, res->u.output_node_info->network_id,
                               sizeof(res->u.output_node_info->network_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NET_ID);
      goto end;
    }

    // parsing bech32HRP
    if ((ret = json_get_string(data_obj, JSON_KEY_BECH32HRP, res->u.output_node_info->bech32hrp,
                               sizeof(res->u.output_node_info->bech32hrp))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_BECH32HRP);
      goto end;
    }

    // gets minPowScore
    if ((ret = json_get_uint64(data_obj, JSON_KEY_MIN_POW, &res->u.output_node_info->min_pow_score)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_MIN_POW);
      goto end;
    }

    // gets latestMilestoneIndex
    if ((ret = json_get_uint64(data_obj, JSON_KEY_LM_IDX, &res->u.output_node_info->latest_milestone_index)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_LM_IDX);
      goto end;
    }

    // gets confirmedMilestoneIndex
    if ((ret = json_get_uint64(data_obj, JSON_KEY_CM_IDX, &res->u.output_node_info->confirmed_milestone_index)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_CM_IDX);
      goto end;
    }

    // gets pruningIndex
    if ((ret = json_get_uint64(data_obj, JSON_KEY_PRUNING_IDX, &res->u.output_node_info->pruning_milestone_index)) !=
        0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_PRUNING_IDX);
      goto end;
    }

    // gets message per second
    if ((ret = json_get_float(data_obj, JSON_KEY_MPS, &res->u.output_node_info->msg_pre_sec)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_MPS);
      goto end;
    }

    // gets referenced message per second
    if ((ret = json_get_float(data_obj, JSON_KEY_REF_MPS, &res->u.output_node_info->referenced_msg_pre_sec)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_REF_MPS);
      goto end;
    }

    // gets referenced rate
    if ((ret = json_get_float(data_obj, JSON_KEY_REF_RATE, &res->u.output_node_info->referenced_rate)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_REF_RATE);
      goto end;
    }

    // gets latest milestone timestamp
    if ((ret = json_get_uint64(data_obj, JSON_KEY_LMT, &res->u.output_node_info->latest_milestone_timestamp)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_LMT);
      goto end;
    }

    // features
    utarray_new(res->u.output_node_info->features, &ut_str_icd);
    if ((ret = json_string_array_to_utarray(data_obj, JSON_KEY_FEATURES, res->u.output_node_info->features)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_FEATURES);
      goto end;
    }
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}