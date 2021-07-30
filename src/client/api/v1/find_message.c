// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/v1/find_message.h"
#include "client/api/json_utils.h"
#include "client/network/http.h"
#include "core/utils/iota_str.h"

static find_msg_t *find_msg_new() {
  find_msg_t *ids = malloc(sizeof(find_msg_t));
  if (ids) {
    ids->count = 0;
    ids->max_results = 0;
    utarray_new(ids->msg_ids, &ut_str_icd);
    return ids;
  }
  return NULL;
}

static void find_msg_free(find_msg_t *ids) {
  if (ids) {
    if (ids->msg_ids) {
      utarray_free(ids->msg_ids);
    }
    free(ids);
  }
}

res_find_msg_t *res_find_msg_new() {
  res_find_msg_t *res = malloc(sizeof(res_find_msg_t));
  if (res) {
    res->is_error = false;
    res->u.msg_ids = NULL;
    return res;
  }
  return NULL;
}

void res_find_msg_free(res_find_msg_t *res) {
  if (res) {
    if (res->is_error) {
      res_err_free(res->u.error);
    } else {
      if (res->u.msg_ids) {
        find_msg_free(res->u.msg_ids);
      }
    }
    free(res);
  }
}

size_t res_find_msg_get_id_len(res_find_msg_t *res) {
  if (res) {
    if (res->is_error == false) {
      if (res->u.msg_ids) {
        return utarray_len(res->u.msg_ids->msg_ids);
      }
    }
  }
  return 0;
}

char *res_find_msg_get_id(res_find_msg_t *res, size_t index) {
  if (res) {
    if (index < res_find_msg_get_id_len(res)) {
      char **p = (char **)utarray_eltptr(res->u.msg_ids->msg_ids, index);
      return *p;
    }
  }
  return NULL;
}

int deser_find_message(char const *const j_str, res_find_msg_t *res) {
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
    // allocate find_msg_t after parsing json object.
    res->u.msg_ids = find_msg_new();
    if (res->u.msg_ids == NULL) {
      printf("[%s:%d]: find_msg_t object allocation filaed\n", __func__, __LINE__);
      goto end;
    }
    // TODO index element?

    // maxResults
    if ((ret = json_get_uint32(data_obj, JSON_KEY_MAX_RESULTS, &res->u.msg_ids->max_results)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MAX_RESULTS);
      goto end;
    }

    // count
    if ((ret = json_get_uint32(data_obj, JSON_KEY_COUNT, &res->u.msg_ids->count)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_COUNT);
      goto end;
    }

    // message IDs
    if ((ret = json_string_array_to_utarray(data_obj, JSON_KEY_MSG_IDS, res->u.msg_ids->msg_ids)) != 0) {
      printf("[%s:%d]: parsing %s failed\n", __func__, __LINE__, JSON_KEY_MSG_IDS);
    }

  } else {
    printf("[%s:%d]: JSON parsing failed\n", __func__, __LINE__);
  }

end:
  cJSON_Delete(json_obj);
  return ret;
}

int find_message_by_index(iota_client_conf_t const *conf, char const index[], res_find_msg_t *res) {
  int ret = -1;
  iota_str_t *cmd = NULL;
  byte_buf_t *http_res = NULL;
  long st = 0;
  // the maximum Index in hex string is 128 bytes plus a null terminator.
  char index_hex[129] = {};

  if (conf == NULL || index == NULL || res == NULL) {
    // invalid parameters
    return -1;
  }
  // the maximum Index is 64 bytes.
  size_t index_str_len = strlen(index);
  if (index_str_len > 64) {
    printf("[%s:%d] index string too long\n", __func__, __LINE__);
    return -1;
  }

  if (string2hex(index, (byte_t *)index_hex, sizeof(index_hex)) != 0) {
    printf("[%s:%d] convert index string to hex failed\n", __func__, __LINE__);
    return -1;
  }

  // compose restful api command
  if ((cmd = iota_str_new("/api/v1/messages?index=")) == NULL) {
    printf("[%s:%d]: cmd append failed\n", __func__, __LINE__);
    return -1;
  }

  if (iota_str_append(cmd, index_hex)) {
    printf("[%s:%d]: index append failed\n", __func__, __LINE__);
    goto done;
  }

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  if ((ret = http_client_get(&http_conf, http_res, &st)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_find_message((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}
