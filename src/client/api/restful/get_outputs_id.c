// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/get_outputs_id.h"
#include "client/api/json_parser/json_utils.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

static get_outputs_id_t *outputs_new() {
  get_outputs_id_t *ids = malloc(sizeof(get_outputs_id_t));
  if (ids) {
    ids->ledger_idx = 0;
    ids->page_size = 0;
    ids->cursor = NULL;
    utarray_new(ids->outputs, &ut_str_icd);
    return ids;
  }
  return NULL;
}

static void outputs_free(get_outputs_id_t *ids) {
  if (ids) {
    if (ids->cursor != NULL) {
      free(ids->cursor);
    }
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

  res->u.output_ids = outputs_new();
  if (res->u.output_ids == NULL) {
    // OOM
    printf("[%s:%d]: allocate output object failed\n", __func__, __LINE__);
    goto end;
  }

  if ((ret = json_get_uint64(json_obj, JSON_KEY_LEDGER_IDX, &res->u.output_ids->ledger_idx) != JSON_OK)) {
    printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_LEDGER_IDX);
    goto end;
  }

  if ((ret = json_get_uint32(json_obj, JSON_KEY_PAGE_SIZE, &res->u.output_ids->page_size) != JSON_OK)) {
    printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_PAGE_SIZE);
    goto end;
  }

  // parse for cursor, it is an optional paramater
  cJSON *json_cursor = cJSON_GetObjectItemCaseSensitive(json_obj, JSON_KEY_CURSOR);
  if (json_cursor != NULL) {
    if (cJSON_IsString(json_cursor) && (json_cursor->valuestring != NULL)) {
      res->u.output_ids->cursor = malloc(strlen(json_cursor->valuestring) + 1);
      memset(res->u.output_ids->cursor, 0, strlen(json_cursor->valuestring) + 1);
      strncpy(res->u.output_ids->cursor, json_cursor->valuestring, strlen(json_cursor->valuestring));
    } else {
      printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_CURSOR);
      ret = JSON_NOT_STRING;
      goto end;
    }
  }

  if ((ret = json_string_array_to_utarray(json_obj, JSON_KEY_ITEMS, res->u.output_ids->outputs)) != JSON_OK) {
    printf("[%s:%d]: gets %s failed\n", __func__, __LINE__, JSON_KEY_ITEMS);
    goto end;
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

static int get_outputs_api_call(iota_client_conf_t const *conf, char *cmd_buffer, res_outputs_id_t *res) {
  // http client configuration
  http_client_config_t http_conf = {
      .host = conf->host, .path = cmd_buffer, .use_tls = conf->use_tls, .port = conf->port};

  byte_buf_t *http_res = NULL;

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    return -1;
  }

  long st = 0;
  int ret = -1;
  // send request via http client
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_outputs((char const *const)http_res->data, res);
  }
  byte_buf_free(http_res);
  return ret;
}

// TODO: handle querry parameters - requiresDustReturn, sender and tag
int get_outputs_from_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res) {
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
  char cmd_buffer[105] = {0};  // 105 = max size of api path(40) + IOTA_ADDRESS_HEX_BYTES(64) + 1
  int snprintf_ret;

  snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/v1/outputs?address=%s", addr);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

// TODO: handle querry parameters - stateController, governor, issuer and sender
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

  // compose restful api command
  char cmd_buffer[77] = {0};  // 77 = max size of api path(36) + ADDRESS_NFT_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/v1/nft?address=%s", addr);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

// TODO: handle querry parameters - requiresDustReturn, sender and tag
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
  char cmd_buffer[81] = {0};  // 81 = max size of api path(40) + ADDRESS_ALIAS_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/v1/aliases?address=%s", addr);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

int get_outputs_from_foundry_address(iota_client_conf_t const *conf, char const addr[], res_outputs_id_t *res) {
  if (conf == NULL || addr == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t addr_len = strlen(addr);
  if (addr_len != ADDRESS_FOUNDRY_HEX_BYTES) {
    printf("[%s:%d] incorrect length of an address\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  char cmd_buffer[83] = {0};  // 83 = max size of api path(42) + ADDRESS_FOUNDRY_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/v1/foundries?address=%s", addr);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

int get_outputs_from_nft_id(iota_client_conf_t const *conf, char const nft_id[], res_outputs_id_t *res) {
  if (conf == NULL || nft_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t id_len = strlen(nft_id);
  if (id_len != ADDRESS_NFT_HEX_BYTES) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  char cmd_buffer[67] = {0};  // 67 = max size of api path(28) + ADDRESS_NFT_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/v1/nft/%s", nft_id);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

int get_outputs_from_alias_id(iota_client_conf_t const *conf, char const alias_id[], res_outputs_id_t *res) {
  if (conf == NULL || alias_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t id_len = strlen(alias_id);
  if (id_len != ADDRESS_ALIAS_HEX_BYTES) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  char cmd_buffer[73] = {0};  // 73 = max size of api path(32) + ADDRESS_ALIAS_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/v1/aliases/%s", alias_id);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}

int get_outputs_from_foundry_id(iota_client_conf_t const *conf, char const foundry_id[], res_outputs_id_t *res) {
  if (conf == NULL || foundry_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t id_len = strlen(foundry_id);
  if (id_len != ADDRESS_FOUNDRY_HEX_BYTES) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  char cmd_buffer[75] = {0};  // 75 = max size of api path(34) + ADDRESS_FOUNDRY_HEX_BYTES(40) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/plugins/indexer/v1/foundries/%s", foundry_id);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    return -1;
  }

  return get_outputs_api_call(conf, cmd_buffer, res);
}
