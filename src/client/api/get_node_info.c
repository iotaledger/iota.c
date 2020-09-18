#include <stdio.h>
#include <stdlib.h>

#include "client/api/get_node_info.h"
#include "client/api/json_utils.h"
#include "client/network/http.h"
#include "client/network/http_buffer.h"
#include "core/iota_str.h"

static char const *const cmd_info = "info";
static char const *const key_name = "name";
static char const *const key_version = "version";
static char const *const key_healthy = "isHealthy";
static char const *const key_net = "operatingNetwork";
static char const *const key_peers = "peers";
static char const *const key_coo_addr = "coordinatorAddress";
static char const *const key_synced = "isSynced";
static char const *const key_lm = "latestMilestoneHash";
static char const *const key_lm_index = "latestMilestoneIndex";
static char const *const key_lsm = "latestSolidMilestoneHash";
static char const *const key_lsm_index = "latestSolidMilestoneIndex";
static char const *const key_pruning = "pruningIndex";
static char const *const key_time = "time";
static char const *const key_features = "features";

int get_node_info(iota_client_conf_t const *conf, res_node_info_t *res) {
  int ret = 0;
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

  http_buf_t *http_res = http_buf_new();
  if (http_res == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    // TODO
    ret = -1;
    goto done;
  }

  // send request via http client
  http_client_get(http_res, &http_conf);
  http_buf2str(http_res);

  // json deserialization
  deser_node_info((char const *const)http_res->data, res);

done:
  // cleanup command
  iota_str_destroy(cmd);
  http_buf_free(http_res);

  return ret;
}

int deser_node_info(char const *const j_str, res_node_info_t *res) {
  int ret = 0;
  cJSON *json_obj = cJSON_Parse(j_str);
  if (json_obj == NULL) {
    return -1;
  }

  // FIXME: dose node info have error?
  // res_err_t *res_err = deser_error(json_obj);
  // if (res_err) {
  //   // got an error response
  //   return -1;
  // }

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, key_data);
  if (data_obj) {
    // gets name
    if ((ret = json_get_string(data_obj, key_name, res->name, sizeof(res->name))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_name);
      ret = -1;
      goto end;
    }

    // gets version
    if ((ret = json_get_string(data_obj, key_version, res->version, sizeof(res->version))) != 0) {
      printf("[%s:%d]: gets %s json string failed\n", __func__, __LINE__, key_version);
      ret = -1;
      goto end;
    }

    // TODO
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}