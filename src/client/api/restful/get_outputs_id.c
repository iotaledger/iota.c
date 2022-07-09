// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/get_outputs_id.h"
#include "client/api/json_parser/json_utils.h"
#include "client/network/http.h"
#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/output_foundry.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"
#include "utlist.h"

#define OUTPUTS_QUERY_ADDRESS_KEY "address"
#define OUTPUTS_QUERY_ALIAS_ADDRESS_KEY "aliasAddress"
#define OUTPUTS_QUERY_HAS_NATIVE_TOKENS_KEY "hasNativeTokens"
#define OUTPUTS_QUERY_MIN_NATIVE_TOKENS_KEY "minNativeTokenCount"
#define OUTPUTS_QUERY_MAX_NATIVE_TOKENS_KEY "maxNativeTokenCount"
#define OUTPUTS_QUERY_STORAGE_RET_KEY "hasStorageReturnCondition"
#define OUTPUTS_QUERY_STORAGE_RET_ADDR_KEY "storageReturnAddress"
#define OUTPUTS_QUERY_HAS_TIMELOCK_KEY "hasTimelockCondition"
#define OUTPUTS_QUERY_TIMELOCKED_BEFORE_KEY "timelockedBefore"
#define OUTPUTS_QUERY_TIMELOCKED_AFTER_KEY "timelockedAfter"
#define OUTPUTS_QUERY_TIMELOCKED_BEFORE_MS_KEY "timelockedBeforeMilestone"
#define OUTPUTS_QUERY_TIMELOCKED_AFTER_MS_KEY "timelockedAfterMilestone"
#define OUTPUTS_QUERY_HAS_EXP_COND_KEY "hasExpirationCondition"
#define OUTPUTS_QUERY_EXPIRES_BEFORE_KEY "expiresBefore"
#define OUTPUTS_QUERY_EXPIRES_AFTER_KEY "expiresAfter"
#define OUTPUTS_QUERY_EXPIRES_BEFORE_MS_KEY "expiresBeforeMilestone"
#define OUTPUTS_QUERY_EXPIRES_AFTER_MS_KEY "expiresAfterMilestone"
#define OUTPUTS_QUERY_EXP_RETURN_ADDR_KEY "expirationReturnAddress"
#define OUTPUTS_QUERY_SENDER_KEY "sender"
#define OUTPUTS_QUERY_TAG_KEY "tag"
#define OUTPUTS_QUERY_CREATED_BEFORE_KEY "createdBefore"
#define OUTPUTS_QUERY_CREATED_AFTER_KEY "createdAfter"
#define OUTPUTS_QUERY_PAGE_SIZE_KEY "pageSize"
#define OUTPUTS_QUERY_CURSOR_KEY "cursor"
#define OUTPUTS_QUERY_STATE_CTRL_KEY "stateController"
#define OUTPUTS_QUERY_GOV_KEY "governor"
#define OUTPUTS_QUERY_ISSUER_KEY "issuer"

#define OUTPUTS_BASIC_PATH "/outputs/basic"
#define OUTPUTS_ALIAS_PATH "/outputs/alias"
#define OUTPUTS_NFT_PATH "/outputs/nft"
#define OUTPUTS_FOUNDRY_PATH "/outputs/foundry"

outputs_query_list_t *outputs_query_list_new() { return NULL; }

int outputs_query_list_add(outputs_query_list_t **list, outputs_query_params_e type, char const *const param) {
  outputs_query_list_t *next = malloc(sizeof(outputs_query_list_t));
  if (next) {
    next->query_item = malloc(sizeof(outputs_query_params_t));
    if (next->query_item) {
      next->query_item->type = type;
      if (type == QUERY_PARAM_TAG) {
        next->query_item->param = malloc(strlen(param) + JSON_HEX_ENCODED_STR_PREFIX_LEN + 1);
      } else {
        next->query_item->param = malloc(strlen(param) + 1);
      }
      if (next->query_item->param) {
        if (type == QUERY_PARAM_TAG) {
          memcpy(next->query_item->param, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN);
          memcpy(next->query_item->param + JSON_HEX_ENCODED_STR_PREFIX_LEN, param, strlen(param) + 1);
        } else {
          memcpy(next->query_item->param, param, strlen(param) + 1);
        }
        LL_APPEND(*list, next);
        return 0;
      } else {
        free(next->query_item);
        free(next);
      }
    } else {
      free(next);
    }
  }
  return -1;
}

size_t get_outputs_query_str_len(outputs_query_list_t *list) {
  size_t query_str_len = 0;
  uint8_t params_seperator_len = 2;  // For "&" params seperator and "=" params assignment
  outputs_query_list_t *elm;
  LL_FOREACH(list, elm) {
    switch (elm->query_item->type) {
      case QUERY_PARAM_ADDRESS:
        query_str_len += strlen(OUTPUTS_QUERY_ADDRESS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_ALIAS_ADDRESS:
        query_str_len += strlen(OUTPUTS_QUERY_ALIAS_ADDRESS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_HAS_NATIVE_TOKENS:
        query_str_len += strlen(OUTPUTS_QUERY_HAS_NATIVE_TOKENS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_MIN_NATIVE_TOKENS:
        query_str_len += strlen(OUTPUTS_QUERY_MIN_NATIVE_TOKENS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_MAX_NATIVE_TOKENS:
        query_str_len += strlen(OUTPUTS_QUERY_MAX_NATIVE_TOKENS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_HAS_STORAGE_RET:
        query_str_len += strlen(OUTPUTS_QUERY_STORAGE_RET_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_STORAGE_RET_ADDR:
        query_str_len += strlen(OUTPUTS_QUERY_STORAGE_RET_ADDR_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_HAS_TIMELOCK:
        query_str_len += strlen(OUTPUTS_QUERY_HAS_TIMELOCK_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_TIMELOCKED_BEFORE:
        query_str_len += strlen(OUTPUTS_QUERY_TIMELOCKED_BEFORE_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_TIMELOCKED_AFTER:
        query_str_len += strlen(OUTPUTS_QUERY_TIMELOCKED_AFTER_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_TIMELOCKED_BEFORE_MS:
        query_str_len += strlen(OUTPUTS_QUERY_TIMELOCKED_BEFORE_MS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_TIMELOCKED_AFTER_MS:
        query_str_len += strlen(OUTPUTS_QUERY_TIMELOCKED_AFTER_MS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_HAS_EXP_COND:
        query_str_len += strlen(OUTPUTS_QUERY_HAS_EXP_COND_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_EXPIRES_BEFORE:
        query_str_len += strlen(OUTPUTS_QUERY_EXPIRES_BEFORE_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_EXPIRES_AFTER:
        query_str_len += strlen(OUTPUTS_QUERY_EXPIRES_AFTER_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_EXPIRES_BEFORE_MS:
        query_str_len += strlen(OUTPUTS_QUERY_EXPIRES_BEFORE_MS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_EXPIRES_AFTER_MS:
        query_str_len += strlen(OUTPUTS_QUERY_EXPIRES_AFTER_MS_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_EXP_RETURN_ADDR:
        query_str_len += strlen(OUTPUTS_QUERY_EXP_RETURN_ADDR_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_SENDER:
        query_str_len += strlen(OUTPUTS_QUERY_SENDER_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_TAG:
        query_str_len += strlen(OUTPUTS_QUERY_TAG_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_CREATED_BEFORE:
        query_str_len += strlen(OUTPUTS_QUERY_CREATED_BEFORE_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_CREATED_AFTER:
        query_str_len += strlen(OUTPUTS_QUERY_CREATED_AFTER_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_PAGE_SIZE:
        query_str_len += strlen(OUTPUTS_QUERY_PAGE_SIZE_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_CURSOR:
        query_str_len += strlen(OUTPUTS_QUERY_CURSOR_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_STATE_CTRL:
        query_str_len += strlen(OUTPUTS_QUERY_STATE_CTRL_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_GOV:
        query_str_len += strlen(OUTPUTS_QUERY_GOV_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      case QUERY_PARAM_ISSUER:
        query_str_len += strlen(OUTPUTS_QUERY_ISSUER_KEY);
        query_str_len += strlen(elm->query_item->param);
        query_str_len += params_seperator_len;
        break;
      default:
        break;
    }
  }
  // check if there was at least one item in the list
  if (query_str_len > 0) {
    query_str_len--;  // Remove the "&" params seperator at the end
  }
  return query_str_len;
}

static int copy_param_to_buf(char *buf, char *key, outputs_query_list_t *elm) {
  int len = 0;
  memcpy(buf + len, key, strlen(key));
  len += strlen(key);
  buf[len++] = '=';
  memcpy(buf + len, elm->query_item->param, strlen(elm->query_item->param));
  len += strlen(elm->query_item->param);
  buf[len++] = '&';
  return len;
}

size_t get_outputs_query_str(outputs_query_list_t *list, char *buf, size_t buf_len) {
  // Check if buffer length is sufficient for holding query string
  size_t query_str_len = get_outputs_query_str_len(list);
  if (query_str_len == 0) {
    printf("[%s:%d] No element in query list\n", __func__, __LINE__);
    return 0;
  }
  if (buf_len < query_str_len + 1) {
    printf("[%s:%d] buffer length not sufficient\n", __func__, __LINE__);
    return 0;
  }

  size_t offset = 0;
  outputs_query_list_t *elm;
  LL_FOREACH(list, elm) {
    switch (elm->query_item->type) {
      case QUERY_PARAM_ADDRESS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_ADDRESS_KEY, elm);
        break;
      case QUERY_PARAM_ALIAS_ADDRESS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_ALIAS_ADDRESS_KEY, elm);
        break;
      case QUERY_PARAM_HAS_NATIVE_TOKENS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_HAS_NATIVE_TOKENS_KEY, elm);
        break;
      case QUERY_PARAM_MIN_NATIVE_TOKENS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_MIN_NATIVE_TOKENS_KEY, elm);
        break;
      case QUERY_PARAM_MAX_NATIVE_TOKENS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_MAX_NATIVE_TOKENS_KEY, elm);
        break;
      case QUERY_PARAM_HAS_STORAGE_RET:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_STORAGE_RET_KEY, elm);
        break;
      case QUERY_PARAM_STORAGE_RET_ADDR:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_STORAGE_RET_ADDR_KEY, elm);
        break;
      case QUERY_PARAM_HAS_TIMELOCK:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_HAS_TIMELOCK_KEY, elm);
        break;
      case QUERY_PARAM_TIMELOCKED_BEFORE:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_TIMELOCKED_BEFORE_KEY, elm);
        break;
      case QUERY_PARAM_TIMELOCKED_AFTER:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_TIMELOCKED_AFTER_KEY, elm);
        break;
      case QUERY_PARAM_TIMELOCKED_BEFORE_MS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_TIMELOCKED_BEFORE_MS_KEY, elm);
        break;
      case QUERY_PARAM_TIMELOCKED_AFTER_MS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_TIMELOCKED_AFTER_MS_KEY, elm);
        break;
      case QUERY_PARAM_HAS_EXP_COND:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_HAS_EXP_COND_KEY, elm);
        break;
      case QUERY_PARAM_EXPIRES_BEFORE:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_EXPIRES_BEFORE_KEY, elm);
        break;
      case QUERY_PARAM_EXPIRES_AFTER:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_EXPIRES_AFTER_KEY, elm);
        break;
      case QUERY_PARAM_EXPIRES_BEFORE_MS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_EXPIRES_BEFORE_MS_KEY, elm);
        break;
      case QUERY_PARAM_EXPIRES_AFTER_MS:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_EXPIRES_AFTER_MS_KEY, elm);
        break;
      case QUERY_PARAM_EXP_RETURN_ADDR:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_EXP_RETURN_ADDR_KEY, elm);
        break;
      case QUERY_PARAM_SENDER:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_SENDER_KEY, elm);
        break;
      case QUERY_PARAM_TAG:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_TAG_KEY, elm);
        break;
      case QUERY_PARAM_CREATED_BEFORE:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_CREATED_BEFORE_KEY, elm);
        break;
      case QUERY_PARAM_CREATED_AFTER:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_CREATED_AFTER_KEY, elm);
        break;
      case QUERY_PARAM_PAGE_SIZE:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_PAGE_SIZE_KEY, elm);
        break;
      case QUERY_PARAM_CURSOR:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_CURSOR_KEY, elm);
        break;
      case QUERY_PARAM_STATE_CTRL:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_STATE_CTRL_KEY, elm);
        break;
      case QUERY_PARAM_GOV:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_GOV_KEY, elm);
        break;
      case QUERY_PARAM_ISSUER:
        offset += copy_param_to_buf(buf + offset, OUTPUTS_QUERY_ISSUER_KEY, elm);
        break;
      default:
        break;
    }
  }
  if (buf[offset - 1] == '&') {
    buf[offset - 1] = 0;  // Replace the "&" at the end with '\0'
  }
  return offset;
}

void outputs_query_list_free(outputs_query_list_t *list) {
  outputs_query_list_t *elm, *tmp;
  if (list) {
    LL_FOREACH_SAFE(list, elm, tmp) {
      free(elm->query_item->param);
      free(elm->query_item);
      LL_DELETE(list, elm);
      free(elm);
    }
  }
}

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

  if ((ret = json_get_uint32(json_obj, JSON_KEY_LEDGER_IDX, &res->u.output_ids->ledger_idx) != JSON_OK)) {
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
      res->u.output_ids->cursor = malloc(strlen(json_cursor->valuestring) - JSON_HEX_ENCODED_STR_PREFIX_LEN + 1);
      strncpy(res->u.output_ids->cursor, json_cursor->valuestring + JSON_HEX_ENCODED_STR_PREFIX_LEN,
              strlen(json_cursor->valuestring) - JSON_HEX_ENCODED_STR_PREFIX_LEN + 1);
    } else {
      printf("[%s:%d] %s is not a string\n", __func__, __LINE__, JSON_KEY_CURSOR);
      ret = JSON_NOT_STRING;
      goto end;
    }
  }

  if ((ret = json_string_with_prefix_array_to_utarray(json_obj, JSON_KEY_ITEMS, res->u.output_ids->outputs)) !=
      JSON_OK) {
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

static char *compose_api_command(outputs_query_list_t *list, char const *const api_path) {
  char *cmd_buffer;
  size_t api_path_len = strlen(api_path);

  if (list) {
    size_t query_str_len = get_outputs_query_str_len(list);
    char *query_str = malloc(query_str_len + 1);
    if (!query_str) {
      printf("[%s:%d]: OOM\n", __func__, __LINE__);
      return NULL;
    }
    size_t len = get_outputs_query_str(list, query_str, query_str_len + 1);
    if (len != query_str_len + 1) {
      printf("[%s:%d]: Query string len and copied data mismatch\n", __func__, __LINE__);
      free(query_str);
      return NULL;
    }
    cmd_buffer = malloc(api_path_len + 1 + query_str_len + 1);  // api_path + '?' + query_str + '\0'
    if (!cmd_buffer) {
      printf("[%s:%d]: OOM\n", __func__, __LINE__);
      return NULL;
    }
    // copy api path
    memcpy(cmd_buffer, api_path, api_path_len);
    // add "?" query symbol
    cmd_buffer[api_path_len] = '?';
    // copy query strings
    memcpy(cmd_buffer + api_path_len + 1, query_str, query_str_len + 1);
    free(query_str);
  } else {
    cmd_buffer = malloc(api_path_len + 1);  // api_path + '\0'
    if (!cmd_buffer) {
      printf("[%s:%d]: OOM\n", __func__, __LINE__);
      return NULL;
    }
    // copy api path
    memcpy(cmd_buffer, api_path, api_path_len + 1);
  }
  return cmd_buffer;
}

int get_basic_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                      res_outputs_id_t *res) {
  if (conf == NULL || indexer_path == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }

  if (strcmp(indexer_path, INDEXER_API_ROUTE) != 0) {
    printf("[%s:%d]: unsupported indexer path\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *api_path = NULL;
  api_path = iota_str_reserve(strlen(indexer_path) + strlen(OUTPUTS_BASIC_PATH) + 1);
  if (api_path == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API path
  snprintf(api_path->buf, api_path->cap, "%s%s", indexer_path, OUTPUTS_BASIC_PATH);
  api_path->len = strlen(api_path->buf);

  // compose restful api command
  char *cmd_buffer = compose_api_command(list, api_path->buf);
  if (cmd_buffer == NULL) {
    iota_str_destroy(api_path);
    return -1;
  }

  int ret = get_outputs_api_call(conf, cmd_buffer, res);
  iota_str_destroy(api_path);
  free(cmd_buffer);
  return ret;
}

int get_nft_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                    res_outputs_id_t *res) {
  if (conf == NULL || indexer_path == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strcmp(indexer_path, INDEXER_API_ROUTE) != 0) {
    printf("[%s:%d]: unsupported indexer path\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *api_path = NULL;
  api_path = iota_str_reserve(strlen(indexer_path) + strlen(OUTPUTS_NFT_PATH) + 1);
  if (api_path == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API path
  snprintf(api_path->buf, api_path->cap, "%s%s", indexer_path, OUTPUTS_NFT_PATH);
  api_path->len = strlen(api_path->buf);

  // compose restful api command
  char *cmd_buffer = compose_api_command(list, api_path->buf);
  if (cmd_buffer == NULL) {
    iota_str_destroy(api_path);
    return -1;
  }

  int ret = get_outputs_api_call(conf, cmd_buffer, res);
  iota_str_destroy(api_path);
  free(cmd_buffer);
  return ret;
}

int get_alias_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                      res_outputs_id_t *res) {
  if (conf == NULL || indexer_path == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strcmp(indexer_path, INDEXER_API_ROUTE) != 0) {
    printf("[%s:%d]: unsupported indexer path\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *api_path = NULL;
  api_path = iota_str_reserve(strlen(indexer_path) + strlen(OUTPUTS_ALIAS_PATH) + 1);
  if (api_path == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API path
  snprintf(api_path->buf, api_path->cap, "%s%s", indexer_path, OUTPUTS_ALIAS_PATH);
  api_path->len = strlen(api_path->buf);

  // compose restful api command
  char *cmd_buffer = compose_api_command(list, api_path->buf);
  if (cmd_buffer == NULL) {
    iota_str_destroy(api_path);
    return -1;
  }

  int ret = get_outputs_api_call(conf, cmd_buffer, res);
  iota_str_destroy(api_path);
  free(cmd_buffer);
  return ret;
}

int get_foundry_outputs(iota_client_conf_t const *conf, char const *const indexer_path, outputs_query_list_t *list,
                        res_outputs_id_t *res) {
  if (conf == NULL || indexer_path == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strcmp(indexer_path, INDEXER_API_ROUTE) != 0) {
    printf("[%s:%d]: unsupported indexer path\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *api_path = NULL;
  api_path = iota_str_reserve(strlen(indexer_path) + strlen(OUTPUTS_FOUNDRY_PATH) + 1);
  if (api_path == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API path
  snprintf(api_path->buf, api_path->cap, "%s%s", indexer_path, OUTPUTS_FOUNDRY_PATH);
  api_path->len = strlen(api_path->buf);

  // compose restful api command
  char *cmd_buffer = compose_api_command(list, api_path->buf);
  if (cmd_buffer == NULL) {
    iota_str_destroy(api_path);
    return -1;
  }

  int ret = get_outputs_api_call(conf, cmd_buffer, res);
  iota_str_destroy(api_path);
  free(cmd_buffer);
  return ret;
}

int get_outputs_from_nft_id(iota_client_conf_t const *conf, char const *const indexer_path, char const nft_id[],
                            res_outputs_id_t *res) {
  if (conf == NULL || indexer_path == NULL || nft_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t id_len = strlen(nft_id);
  if (id_len != BIN_TO_HEX_BYTES(NFT_ID_BYTES)) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  if (strcmp(indexer_path, INDEXER_API_ROUTE) != 0) {
    printf("[%s:%d]: unsupported indexer path\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *api_path = NULL;
  // api_path = indexer_path + OUTPUTS_NFT_PATH + '/0x' + nft_id + '\0'
  api_path = iota_str_reserve(strlen(indexer_path) + strlen(OUTPUTS_NFT_PATH) + 3 + BIN_TO_HEX_BYTES(NFT_ID_BYTES) + 1);
  if (api_path == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API path
  snprintf(api_path->buf, api_path->cap, "%s%s/0x%s", indexer_path, OUTPUTS_NFT_PATH, nft_id);
  api_path->len = strlen(api_path->buf);

  int ret = get_outputs_api_call(conf, api_path->buf, res);
  iota_str_destroy(api_path);
  return ret;
}

int get_outputs_from_alias_id(iota_client_conf_t const *conf, char const *const indexer_path, char const alias_id[],
                              res_outputs_id_t *res) {
  if (conf == NULL || indexer_path == NULL || alias_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t id_len = strlen(alias_id);
  if (id_len != BIN_TO_HEX_BYTES(ALIAS_ID_BYTES)) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  if (strcmp(indexer_path, INDEXER_API_ROUTE) != 0) {
    printf("[%s:%d]: unsupported indexer path\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *api_path = NULL;
  // api_path = indexer_path + OUTPUTS_ALIAS_PATH + '/0x' + alias_id + '\0'
  api_path =
      iota_str_reserve(strlen(indexer_path) + strlen(OUTPUTS_ALIAS_PATH) + 3 + BIN_TO_HEX_BYTES(ALIAS_ID_BYTES) + 1);
  if (api_path == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API path
  snprintf(api_path->buf, api_path->cap, "%s%s/0x%s", indexer_path, OUTPUTS_ALIAS_PATH, alias_id);
  api_path->len = strlen(api_path->buf);

  int ret = get_outputs_api_call(conf, api_path->buf, res);
  iota_str_destroy(api_path);
  return ret;
}

int get_outputs_from_foundry_id(iota_client_conf_t const *conf, char const *const indexer_path, char const foundry_id[],
                                res_outputs_id_t *res) {
  if (conf == NULL || indexer_path == NULL || foundry_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  size_t id_len = strlen(foundry_id);
  if (id_len != BIN_TO_HEX_BYTES(FOUNDRY_ID_BYTES)) {
    printf("[%s:%d] incorrect length of id\n", __func__, __LINE__);
    return -1;
  }

  if (strcmp(indexer_path, INDEXER_API_ROUTE) != 0) {
    printf("[%s:%d]: unsupported indexer path\n", __func__, __LINE__);
    return -1;
  }

  iota_str_t *api_path = NULL;
  // api_path =  indexer_path + OUTPUTS_FOUNDRY_PATH + '/0x' + foundry_id + '\0'
  api_path = iota_str_reserve(strlen(indexer_path) + strlen(OUTPUTS_FOUNDRY_PATH) + 3 +
                              BIN_TO_HEX_BYTES(FOUNDRY_ID_BYTES) + 1);
  if (api_path == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API path
  snprintf(api_path->buf, api_path->cap, "%s%s/0x%s", indexer_path, OUTPUTS_FOUNDRY_PATH, foundry_id);
  api_path->len = strlen(api_path->buf);

  int ret = get_outputs_api_call(conf, api_path->buf, res);
  iota_str_destroy(api_path);
  return ret;
}
