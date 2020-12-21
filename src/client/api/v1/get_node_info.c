#include <stdio.h>
#include <stdlib.h>

#include "client/api/json_utils.h"
#include "client/api/v1/get_node_info.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

res_node_info_t *res_node_info_new() {
  res_node_info_t *res = malloc(sizeof(res_node_info_t));
  res->is_error = false;
  return res;
}

void res_node_info_free(res_node_info_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      free(res->u.output_node_info);
    }
    free(res);
  }
}

int get_node_info(iota_client_conf_t const *conf, res_node_info_t *res) {
  int ret = 0;
  char const *const cmd_info = "api/v1/info";
  // compose restful api command
  iota_str_t *cmd = iota_str_new(conf->url);
  if (cmd == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, cmd_info)) {
    printf("[%s:%d]: string append failed\n", __func__, __LINE__);
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
    deser_node_info((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);

  return ret;
}

int deser_node_info(char const *const j_str, res_node_info_t *res) {
  char const *const key_name = "name";
  char const *const key_version = "version";
  char const *const key_healthy = "isHealthy";
  char const *const key_net = "networkId";
  char const *const key_lm_index = "latestMilestoneIndex";
  char const *const key_sm_index = "solidMilestoneIndex";
  char const *const key_pruning = "pruningIndex";
  char const *const key_features = "features";
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
    ret = 0;
    goto end;
  }

  res->u.output_node_info = malloc(sizeof(get_node_info_t));
  if (res->u.output_node_info == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return -1;
  }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    // gets name
    if ((ret = json_get_string(data_obj, key_name, res->u.output_node_info->name,
                               sizeof(res->u.output_node_info->name))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_name);
      ret = -1;
      goto end;
    }

    // gets version
    if ((ret = json_get_string(data_obj, key_version, res->u.output_node_info->version,
                               sizeof(res->u.output_node_info->version))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_version);
      ret = -1;
      goto end;
    }

    // gets isHealthy
    if ((ret = json_get_boolean(data_obj, key_healthy, &res->u.output_node_info->is_healthy)) != 0) {
      printf("[%s:%d]: gets %s json boolean failed\n", __func__, __LINE__, key_healthy);
      ret = -1;
      goto end;
    }

    // gets networkId
    if ((ret = json_get_string(data_obj, key_net, res->u.output_node_info->network_id,
                               sizeof(res->u.output_node_info->network_id))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_net);
      ret = -1;
      goto end;
    }

    // gets latestMilestoneIndex
    if ((ret = json_get_uint64(data_obj, key_lm_index, &res->u.output_node_info->latest_milestone_index)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_lm_index);
      ret = -1;
      goto end;
    }

    // gets solidMilestoneIndex
    if ((ret = json_get_uint64(data_obj, key_sm_index, &res->u.output_node_info->solid_milestone_index)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_sm_index);
      ret = -1;
      goto end;
    }

    // gets pruningIndex
    if ((ret = json_get_uint64(data_obj, key_pruning, &res->u.output_node_info->pruning_milestone_index)) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_pruning);
      ret = -1;
      goto end;
    }

    // TODO: gets features
    // if ((ret = json_string_array_to_utarray(data_obj, key_features, res->u.output_node_info->features)) != 0) {
    //   printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_features);
    //   ret = -1;
    //   goto end;
    // }
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}