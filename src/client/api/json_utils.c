// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_utils.h"

json_error_t json_get_string(cJSON const* const obj, char const key[], char str[], size_t str_len) {
  if (obj == NULL || key == NULL || str == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsString(json_value) && (json_value->valuestring != NULL)) {
    strncpy(str, json_value->valuestring, str_len);
  } else {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, key);
    return JSON_NOT_STRING;
  }

  return JSON_OK;
}

json_error_t json_get_byte_buf_str(cJSON const* const obj, char const key[], byte_buf_t* buf) {
  if (obj == NULL || key == NULL || buf == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsString(json_value) && (json_value->valuestring != NULL)) {
    // append the string with null terminator to byte_buf
    byte_buf_append(buf, (byte_t const*)json_value->valuestring, strlen((char const*)json_value->valuestring) + 1);
  } else {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, key);
    return JSON_NOT_STRING;
  }

  return JSON_OK;
}

json_error_t json_get_boolean(cJSON const* const obj, char const key[], bool* const boolean) {
  if (obj == NULL || key == NULL || boolean == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsBool(json_value)) {
    *boolean = cJSON_IsTrue(json_value);
  } else {
    printf("[%s:%d] %s is not a boolean\n", __func__, __LINE__, key);
    return JSON_NOT_BOOL;
  }

  return JSON_OK;
}

json_error_t json_string_array_to_utarray(cJSON const* const obj, char const key[], UT_array* ut) {
  if (obj == NULL || key == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  char* str = NULL;
  cJSON* json_item = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_item == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsArray(json_item)) {
    cJSON* current_obj = NULL;
    cJSON_ArrayForEach(current_obj, json_item) {
      str = cJSON_GetStringValue(current_obj);
      if (!str) {
        printf("[%s:%d] encountered non-string array member", __func__, __LINE__);
        return JSON_ERR;
      }
      utarray_push_back(ut, &str);
    }
  } else {
    printf("[%s:%d] %s is not an array object\n", __func__, __LINE__, key);
    return JSON_NOT_ARRAY;
  }

  return JSON_OK;
}

json_error_t utarray_to_json_string_array(UT_array const* const ut, cJSON* const json_obj, char const* const key) {
  cJSON* array_obj = cJSON_CreateArray();
  char** p = NULL;

  if (!ut || !json_obj || !key) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  if (array_obj == NULL) {
    printf("[%s:%d] create json array failed\n", __func__, __LINE__);
    return JSON_CREATE_FAILED;
  }

  cJSON_AddItemToObject(json_obj, key, array_obj);

  while ((p = (char**)utarray_next(ut, p))) {
    cJSON_AddItemToArray(array_obj, cJSON_CreateString(*p));
  }
  return JSON_OK;
}

json_error_t json_get_int(cJSON const* const obj, char const key[], int* const num) {
  if (obj == NULL || key == NULL || num == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsNumber(json_value)) {
    *num = json_value->valueint;
  } else {
    printf("[%s:%d] %s is not an number\n", __func__, __LINE__, key);
    return JSON_NOT_NUMBER;
  }

  return JSON_OK;
}

json_error_t json_get_uint8(cJSON const* const obj, char const key[], uint8_t* const num) {
  if (obj == NULL || key == NULL || num == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsNumber(json_value)) {
    if (json_value->valueint >= 0) {
      *num = (uint8_t)json_value->valueint;
    } else {
      printf("[%s:%d] %s is not an unsigned number\n", __func__, __LINE__, key);
      return JSON_NOT_UNSIGNED;
    }
  } else {
    printf("[%s:%d] %s is not an number\n", __func__, __LINE__, key);
    return JSON_NOT_NUMBER;
  }

  return JSON_OK;
}

json_error_t json_get_uint16(cJSON const* const obj, char const key[], uint16_t* const num) {
  if (obj == NULL || key == NULL || num == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsNumber(json_value)) {
    if (json_value->valueint >= 0) {
      *num = (uint16_t)json_value->valueint;
    } else {
      printf("[%s:%d] %s is not an unsigned number\n", __func__, __LINE__, key);
      return JSON_NOT_UNSIGNED;
    }
  } else {
    printf("[%s:%d] %s is not an number\n", __func__, __LINE__, key);
    return JSON_NOT_NUMBER;
  }

  return JSON_OK;
}

json_error_t json_get_uint32(cJSON const* const obj, char const key[], uint32_t* const num) {
  if (obj == NULL || key == NULL || num == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsNumber(json_value)) {
    if (json_value->valueint >= 0) {
      *num = (uint32_t)json_value->valuedouble;
    } else {
      printf("[%s:%d] %s is not an unsigned number\n", __func__, __LINE__, key);
      return JSON_NOT_UNSIGNED;
    }
  } else {
    printf("[%s:%d] %s is not an number\n", __func__, __LINE__, key);
    return JSON_NOT_NUMBER;
  }

  return JSON_OK;
}

json_error_t json_get_uint64(cJSON const* const obj, char const key[], uint64_t* const num) {
  if (obj == NULL || key == NULL || num == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsNumber(json_value)) {
    if (json_value->valueint >= 0) {
      *num = (uint64_t)json_value->valuedouble;
    } else {
      printf("[%s:%d] %s is not an unsigned number\n", __func__, __LINE__, key);
      return JSON_NOT_UNSIGNED;
    }
  } else {
    printf("[%s:%d] %s is not an number\n", __func__, __LINE__, key);
    return JSON_NOT_NUMBER;
  }

  return JSON_OK;
}

json_error_t json_get_float(cJSON const* const obj, char const key[], float* const f) {
  if (obj == NULL || key == NULL || f == NULL) {
    // invalid parameters
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsNumber(json_value)) {
    if (json_value->valueint >= 0) {
      *f = (float)json_value->valuedouble;
    } else {
      printf("[%s:%d] %s is not an unsigned number\n", __func__, __LINE__, key);
      return JSON_NOT_UNSIGNED;
    }
  } else {
    printf("[%s:%d] %s is not an number\n", __func__, __LINE__, key);
    return JSON_NOT_NUMBER;
  }

  return JSON_OK;
}
