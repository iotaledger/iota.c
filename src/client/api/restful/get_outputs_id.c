// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/get_outputs_id.h"
#include "client/api/json_utils.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

static get_outputs_id_t *outputs_new() {
  get_outputs_id_t *ids = malloc(sizeof(get_outputs_id_t));
  if (ids) {
    ids->count = 0;
    ids->max_results = 0;
    utarray_new(ids->outputs, &ut_str_icd);
    return ids;
  }
  return NULL;
}

static void outputs_free(get_outputs_id_t *ids) {
  if (ids) {
    if (ids->outputs) {
      utarray_free(ids->outputs);
    }
    free(ids);
  }
}

res_outputs_id_t *res_outputs_new() {
  res_outputs_id_t *res = malloc(sizeof(res_outputs_id_t));
  if (res) {
    res->is_error = false;
    res->u.output_ids = NULL;
    return res;
  }
  return NULL;
}

void res_outputs_free(res_outputs_id_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.output_ids) {
        outputs_free(res->u.output_ids);
      }
    }
    free(res);
  }
}

char *res_outputs_output_id(res_outputs_id_t *res, size_t index) {
  if (res == NULL) {
    return NULL;
  }

  if (utarray_len(res->u.output_ids->outputs)) {
    char **p = (char **)utarray_eltptr(res->u.output_ids->outputs, index);
    return *p;
  }
  return NULL;
}

size_t res_outputs_output_id_count(res_outputs_id_t *res) {
  if (res == NULL) {
    return 0;
  }
  return utarray_len(res->u.output_ids->outputs);
}
int deser_outputs(char const *const j_str, res_outputs_id_t *res) {
  int ret = -1;
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

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

  cJSON *data_obj = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_DATA);
  if (data_obj) {
    res->u.output_ids = outputs_new();
    if (res->u.output_ids == NULL) {
      // OOM
      printf("[%s:%d]: allocate output object failed\n", __func__, __LINE__);
      goto end;
    }

    if ((ret = json_get_uint32(data_obj, JSON_KEY_MAX_RESULTS, &res->u.output_ids->max_results) != 0)) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_MAX_RESULTS);
      goto end;
    }

    if ((ret = json_get_uint32(data_obj, JSON_KEY_COUNT, &res->u.output_ids->count) != 0)) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_COUNT);
      goto end;
    }

    if ((ret = json_string_array_to_utarray(data_obj, JSON_KEY_OUTPUT_IDS, res->u.output_ids->outputs)) != 0) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_OUTPUT_IDS);
      goto end;
    }

    if ((ret = json_get_uint64(data_obj, JSON_KEY_LEDGER_IDX, &res->u.output_ids->ledger_idx) != 0)) {
      printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_LEDGER_IDX);
      goto end;
    }

  } else {
    // JSON format mismatched.
    printf("[%s:%d]: parsing JSON object failed\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

static int get_outputs_api_call(iota_client_conf_t const *conf, char *cmd_buffer, res_outputs_id_t *res) {
  int ret = -1;

  // http client configuration
  http_client_config_t http_conf = {
      .host = conf->host, .path = cmd_buffer, .use_tls = conf->use_tls, .port = conf->port};

  byte_buf_t *http_res = NULL;
  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long st = 0;
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_outputs((char const *const)http_res->data, res);
  }

done:
  // Cleanup http_res buffer
  byte_buf_free(http_res);
  return ret;
}

int get_outputs_from_address(iota_client_conf_t const *conf, bool is_bech32, char const addr[], res_outputs_id_t *res) {
  if (conf == NULL || addr == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }

  size_t addr_len = strlen(addr);
  if (addr_len != ADDRESS_ED25519_HEX_BYTES) {
    printf("[%s:%d] incorrect length of the address\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  char cmd_buffer[112] = {0};  // 99 = max size of api path(47) + IOTA_ADDRESS_HEX_BYTES(64) + 1
  int snprintf_ret;

  if (is_bech32) {
    snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/addresses/%s/outputs", addr);
  } else {
    snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/addresses/ed25519/%s/outputs", addr);
  }

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

int get_outputs_from_nft_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res) {
  if (conf == NULL || addr == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t addr_len = strlen(addr);
  if (addr_len != ADDRESS_NFT_HEX_BYTES) {
    printf("[%s:%d] incorrect length of an address\n", __func__, __LINE__);
    return -1;
  }

  int ret = -1;

  // compose restful api command
  char cmd_buffer[84] = {0};  // 84 = max size of api path(43) + ADDRESS_NFT_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/addresses/nft/%s/outputs", addr);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

int get_outputs_from_alias_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res) {
  if (conf == NULL || addr == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t addr_len = strlen(addr);
  if (addr_len != ADDRESS_ALIAS_HEX_BYTES) {
    printf("[%s:%d] incorrect length of an address\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  char cmd_buffer[86] = {0};  // 86 = max size of api path(45) + ADDRESS_ALIAS_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/addresses/alias/%s/outputs", addr);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}
