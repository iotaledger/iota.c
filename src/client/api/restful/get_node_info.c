// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_parser/json_utils.h"
#include "client/api/restful/get_node_info.h"
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
        if (res->u.output_node_info->plugins) {
          utarray_free(res->u.output_node_info->plugins);
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

char *get_node_plugins_at(res_node_info_t *info, size_t idx) {
  if (info == NULL) {
    printf("[%s:%d]: get plugins failed (null parameter)\n", __func__, __LINE__);
    return NULL;
  }

  int len = utarray_len(info->u.output_node_info->plugins);
  if (idx >= len) {
    printf("[%s:%d]: get plugins failed (invalid index)\n", __func__, __LINE__);
    return NULL;
  }

  return *(char **)utarray_eltptr(info->u.output_node_info->plugins, idx);
}

size_t get_node_plugins_num(res_node_info_t *info) {
  if (info == NULL) {
    printf("[%s:%d]: get_plugins failed (null parameter)\n", __func__, __LINE__);
    return 0;
  }

  return utarray_len(info->u.output_node_info->plugins);
}

int get_node_info(iota_client_conf_t const *conf, res_node_info_t *res) {
  int ret = 0;
  char const *const cmd_info = "/api/v2/info";
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

  // gets name
  if ((ret = json_get_string(json_obj, JSON_KEY_NAME, res->u.output_node_info->name,
                             sizeof(res->u.output_node_info->name))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NAME);
    goto end;
  }

  // gets version
  if ((ret = json_get_string(json_obj, JSON_KEY_VER, res->u.output_node_info->version,
                             sizeof(res->u.output_node_info->version))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_VER);
    goto end;
  }

  cJSON *status_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_STATUS);

  // gets isHealthy
  if ((ret = json_get_boolean(status_obj, JSON_KEY_IS_HEALTHY, &res->u.output_node_info->is_healthy)) != 0) {
    printf("[%s:%d]: gets %s json boolean failed\n", __func__, __LINE__, JSON_KEY_IS_HEALTHY);
    goto end;
  }

  // gets latest milestone timestamp
  if ((ret = json_get_uint64(status_obj, JSON_KEY_LMT, &res->u.output_node_info->latest_milestone_timestamp)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_LMT);
    goto end;
  }

  // gets latestMilestoneIndex
  if ((ret = json_get_uint64(status_obj, JSON_KEY_LM_IDX, &res->u.output_node_info->latest_milestone_index)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_LM_IDX);
    goto end;
  }

  // gets confirmedMilestoneIndex
  if ((ret = json_get_uint64(status_obj, JSON_KEY_CM_IDX, &res->u.output_node_info->confirmed_milestone_index)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_CM_IDX);
    goto end;
  }

  // gets pruningIndex
  if ((ret = json_get_uint64(status_obj, JSON_KEY_PRUNING_IDX, &res->u.output_node_info->pruning_milestone_index)) !=
      0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_PRUNING_IDX);
    goto end;
  }

  cJSON *metrics_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_METRICS);

  // gets message per second
  if ((ret = json_get_float(metrics_obj, JSON_KEY_MPS, &res->u.output_node_info->msg_per_sec)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_MPS);
    goto end;
  }

  // gets referenced message per second
  if ((ret = json_get_float(metrics_obj, JSON_KEY_REF_MPS, &res->u.output_node_info->referenced_msg_per_sec)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_REF_MPS);
    goto end;
  }

  // gets referenced rate
  if ((ret = json_get_float(metrics_obj, JSON_KEY_REF_RATE, &res->u.output_node_info->referenced_rate)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_REF_RATE);
    goto end;
  }

  cJSON *protocol_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_PROTOCOL);

  // gets network name
  if ((ret = json_get_string(protocol_obj, JSON_KEY_NET_NAME, res->u.output_node_info->network_name,
                             sizeof(res->u.output_node_info->network_name))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_NET_NAME);
    goto end;
  }

  // parsing bech32HRP
  if ((ret = json_get_string(protocol_obj, JSON_KEY_BECH32HRP, res->u.output_node_info->bech32hrp,
                             sizeof(res->u.output_node_info->bech32hrp))) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_BECH32HRP);
    goto end;
  }

  // gets minPowScore
  if ((ret = json_get_uint64(protocol_obj, JSON_KEY_MIN_POW, &res->u.output_node_info->min_pow_score)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_MIN_POW);
    goto end;
  }

  cJSON *rent_struct_obj = cJSON_GetObjectItemCaseSensitive(protocol_obj, JSON_KEY_RENT_STRUCTURE);

  // gets vByteCost
  if ((ret = json_get_uint16(rent_struct_obj, JSON_KEY_BYTE_COST, &res->u.output_node_info->v_byte_cost)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_BYTE_COST);
    goto end;
  }

  // gets vByteFactorData
  if ((ret = json_get_uint8(rent_struct_obj, JSON_KEY_BYTE_FACTOR_DATA,
                            &res->u.output_node_info->v_byte_factor_data)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_BYTE_FACTOR_DATA);
    goto end;
  }

  // gets vByteFactorKey
  if ((ret = json_get_uint8(rent_struct_obj, JSON_KEY_BYTE_FACTOR_KEY, &res->u.output_node_info->v_byte_factor_key)) !=
      0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_BYTE_FACTOR_KEY);
    goto end;
  }

  // features
  utarray_new(res->u.output_node_info->features, &ut_str_icd);
  if ((ret = json_string_array_to_utarray(json_obj, JSON_KEY_FEATURES, res->u.output_node_info->features)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_FEATURES);
    goto end;
  }

  // plugins
  utarray_new(res->u.output_node_info->plugins, &ut_str_icd);
  if ((ret = json_string_array_to_utarray(json_obj, JSON_KEY_PLUGINS, res->u.output_node_info->plugins)) != 0) {
    printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, JSON_KEY_PLUGINS);
    goto end;
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

void node_info_print(res_node_info_t *res, uint8_t indentation) {
  if (res == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return;
  }
  if (res->is_error) {
    printf("Error: %s\n", res->u.error->msg);
  } else {
    get_node_info_t *info = res->u.output_node_info;
    printf("%s{\n", PRINT_INDENTATION(indentation));
    printf("%s\tname: %s\n", PRINT_INDENTATION(indentation), info->name);
    printf("%s\tversion: %s\n", PRINT_INDENTATION(indentation), info->version);

    printf("%s\tstatus:{\n", PRINT_INDENTATION(indentation));
    printf("%s\t\tisHealthy: %s\n", PRINT_INDENTATION(indentation), info->is_healthy ? "True" : "False");
    printf("%s\t\tlatestMilestoneTimestamp: %" PRIu64 "\n", PRINT_INDENTATION(indentation),
           info->latest_milestone_timestamp);
    printf("%s\t\tlatestMilestoneIndex: %" PRIu64 "\n", PRINT_INDENTATION(indentation), info->latest_milestone_index);
    printf("%s\t\tconfirmedMilestoneIndex: %" PRIu64 "\n", PRINT_INDENTATION(indentation),
           info->confirmed_milestone_index);
    printf("%s\t\tpruningIndex: %" PRIu64 "\n", PRINT_INDENTATION(indentation), info->pruning_milestone_index);
    printf("%s\t}\n", PRINT_INDENTATION(indentation));

    printf("%s\tmetrics:{\n", PRINT_INDENTATION(indentation));
    printf("%s\t\tmessagesPerSecond: %f\n", PRINT_INDENTATION(indentation), info->msg_per_sec);
    printf("%s\t\treferencedMessagesPerSecond: %f\n", PRINT_INDENTATION(indentation), info->referenced_msg_per_sec);
    printf("%s\t\treferencedRate: %f\n", PRINT_INDENTATION(indentation), info->referenced_rate);
    printf("%s\t}\n", PRINT_INDENTATION(indentation));

    printf("%s\tprotocol:{\n", PRINT_INDENTATION(indentation));
    printf("%s\t\tnetworkName: %s\n", PRINT_INDENTATION(indentation), info->network_name);
    printf("%s\t\tbech32HRP: %s\n", PRINT_INDENTATION(indentation), info->bech32hrp);
    printf("%s\t\tminPoWScore: %" PRIu64 "\n", PRINT_INDENTATION(indentation), info->min_pow_score);
    printf("%s\t\trentStructure:{\n", PRINT_INDENTATION(indentation));
    printf("%s\t\t\tvByteCost: %" PRIu16 "\n", PRINT_INDENTATION(indentation), info->v_byte_cost);
    printf("%s\t\t\tvByteFactorData: %" PRIu8 "\n", PRINT_INDENTATION(indentation), info->v_byte_factor_data);
    printf("%s\t\t\tvByteFactorKey: %" PRIu8 "\n", PRINT_INDENTATION(indentation), info->v_byte_factor_key);
    printf("%s\t\t}{\n", PRINT_INDENTATION(indentation));
    printf("%s\t}\n", PRINT_INDENTATION(indentation));

    printf("%s\tfeatures: [\n", PRINT_INDENTATION(indentation));
    int len = utarray_len(info->features);
    for (int i = 0; i < len; i++) {
      printf(i > 0 ? ",\n" : "");
      printf("%s\t\t%s", PRINT_INDENTATION(indentation), *(char **)utarray_eltptr(info->features, i));
    }
    printf("\n");
    printf("%s\t],\n", PRINT_INDENTATION(indentation));
    printf("%s\tplugins: [\n", PRINT_INDENTATION(indentation));
    len = utarray_len(info->plugins);
    for (int i = 0; i < len; i++) {
      printf(i > 0 ? ",\n" : "");
      printf("%s\t\t%s", PRINT_INDENTATION(indentation), *(char **)utarray_eltptr(info->plugins, i));
    }
    printf("\n");
    printf("%s\t]\n", PRINT_INDENTATION(indentation));
    printf("%s}\n", PRINT_INDENTATION(indentation));
  }
}
