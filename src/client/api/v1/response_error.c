// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_keys.h"
#include "client/api/v1/response_error.h"
#include "core/utils/allocator.h"

void res_err_free(res_err_t *err) {
  if (err) {
    if (err->code) {
      free(err->code);
    }

    if (err->msg) {
      free(err->msg);
    }

    free(err);
  }
}

res_err_t *deser_error(cJSON *j_obj) {
  if (j_obj == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return NULL;
  }

  // check if it is an error response;
  cJSON *err_obj = cJSON_GetObjectItemCaseSensitive(j_obj, JSON_KEY_ERROR);
  if (err_obj == NULL) {
    // it is not exactly an error
    // printf("INFO [%s:%d]: error object not found in this response\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *err_code = cJSON_GetObjectItemCaseSensitive(err_obj, JSON_KEY_CODE);
  if (!err_code) {
    printf("[%s:%d]: error code found\n", __func__, __LINE__);
    return NULL;
  }
  if (!cJSON_IsString(err_code) || (err_code->valuestring == NULL)) {
    printf("[%s:%d] error message is not a string\n", __func__, __LINE__);
    return NULL;
  }

  cJSON *err_msg = cJSON_GetObjectItemCaseSensitive(err_obj, JSON_KEY_MSG);
  if (err_msg == NULL) {
    printf("[%s:%d] error message not found\n", __func__, __LINE__);
    return NULL;
  }
  if (!cJSON_IsString(err_msg) || (err_msg->valuestring == NULL)) {
    printf("[%s:%d] error message is not a string\n", __func__, __LINE__);
    return NULL;
  }

  res_err_t *res_err = malloc(sizeof(res_err_t));
  if (res_err == NULL) {
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }

  size_t len = strlen(err_msg->valuestring);
  res_err->msg = malloc(len + 1);
  if (res_err->msg == NULL) {
    res_err_free(res_err);
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  strncpy(res_err->msg, err_msg->valuestring, len);
  res_err->msg[len] = '\0';

  len = strlen(err_code->valuestring);
  res_err->code = malloc(len + 1);
  if (res_err->code == NULL) {
    res_err_free(res_err);
    printf("[%s:%d] OOM\n", __func__, __LINE__);
    return NULL;
  }
  strncpy(res_err->code, err_code->valuestring, len);
  res_err->code[len] = '\0';

  return res_err;
}