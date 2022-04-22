// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "client/api/json_parser/json_utils.h"

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

json_error_t json_get_string_with_prefix(cJSON const* const obj, char const key[], char str[], size_t str_len) {
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
    if (memcmp(json_value->valuestring, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
      printf("[%s:%d] hex string without %s prefix \n", __func__, __LINE__, JSON_HEX_ENCODED_STRING_PREFIX);
      return JSON_NOT_HEX_STRING;
    }
    strncpy(str, json_value->valuestring + JSON_HEX_ENCODED_STR_PREFIX_LEN, str_len);
  } else {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, key);
    return JSON_NOT_STRING;
  }

  return JSON_OK;
}

json_error_t json_get_hex_str_to_bin(cJSON const* const obj, char const key[], byte_t bin[], size_t bin_len) {
  if (obj == NULL || key == NULL || bin == NULL) {
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
    if (memcmp(json_value->valuestring, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
      printf("[%s:%d] hex string without %s prefix \n", __func__, __LINE__, JSON_HEX_ENCODED_STRING_PREFIX);
      return JSON_NOT_HEX_STRING;
    }
    if (hex_2_bin(json_value->valuestring, strlen(json_value->valuestring), JSON_HEX_ENCODED_STRING_PREFIX, bin,
                  bin_len) != 0) {
      printf("[%s:%d] hex string to bin error\n", __func__, __LINE__);
      return JSON_ERR;
    }
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
    if (memcmp(json_value->valuestring, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
      printf("[%s:%d] hex string without %s prefix \n", __func__, __LINE__, JSON_HEX_ENCODED_STRING_PREFIX);
      return JSON_NOT_HEX_STRING;
    }
    // append the string with null terminator to byte_buf
    byte_buf_append(buf, (byte_t const*)(json_value->valuestring + JSON_HEX_ENCODED_STR_PREFIX_LEN),
                    strlen((char const*)json_value->valuestring) - JSON_HEX_ENCODED_STR_PREFIX_LEN + 1);
  } else {
    printf("[%s:%d] %s is not a string\n", __func__, __LINE__, key);
    return JSON_NOT_STRING;
  }

  return JSON_OK;
}

json_error_t json_get_bin_buf_str(cJSON const* const obj, char const key[], byte_buf_t* buf) {
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
    size_t str_len = strlen(json_value->valuestring);

    if (str_len >= 2) {
      if (memcmp(json_value->valuestring, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
        printf("[%s:%d] hex string without %s prefix\n", __func__, __LINE__, JSON_HEX_ENCODED_STRING_PREFIX);
        return JSON_NOT_HEX_STRING;
      }
    } else {
      printf("[%s:%d] hex string length too small\n", __func__, __LINE__);
      return JSON_NOT_HEX_STRING;
    }

    size_t bin_len = (str_len - JSON_HEX_ENCODED_STR_PREFIX_LEN) / 2;
    if (bin_len == 0) {
      printf("[%s:%d] zero length hex string\n", __func__, __LINE__);
      return JSON_OK;
    }
    byte_t* bin_elm = calloc(1, bin_len);
    if (!bin_elm) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      return JSON_MEMORY_ERROR;
    }

    // convert hex string to binary
    if (hex_2_bin(json_value->valuestring, str_len, JSON_HEX_ENCODED_STRING_PREFIX, bin_elm, bin_len) == 0) {
      byte_buf_append(buf, bin_elm, bin_len);
      free(bin_elm);
    } else {
      printf("[%s:%d] convert hex string to binary error\n", __func__, __LINE__);
      free(bin_elm);
      return JSON_ERR;
    }
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

json_error_t json_string_with_prefix_array_to_utarray(cJSON const* const obj, char const key[], UT_array* ut) {
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
      if (memcmp(str, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
        printf("[%s:%d] hex string without %s prefix \n", __func__, __LINE__, JSON_HEX_ENCODED_STRING_PREFIX);
        return JSON_NOT_HEX_STRING;
      }
      char* str_without_prefix = str + JSON_HEX_ENCODED_STR_PREFIX_LEN;
      utarray_push_back(ut, &str_without_prefix);
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
    size_t str_len = strlen(*p);
    char* str_without_prefix = malloc(str_len + JSON_HEX_ENCODED_STR_PREFIX_LEN + 1);  // Zero terminate string
    if (!str_without_prefix) {
      printf("[%s:%d] OOM\n", __func__, __LINE__);
      return JSON_MEMORY_ERROR;
    }

    memcpy(str_without_prefix, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN);
    memcpy(str_without_prefix + JSON_HEX_ENCODED_STR_PREFIX_LEN, *p, str_len);
    memset(str_without_prefix + JSON_HEX_ENCODED_STR_PREFIX_LEN + str_len, 0, 1);

    if (!cJSON_AddItemToArray(array_obj, cJSON_CreateString(str_without_prefix))) {
      printf("[%s:%d] can not create JSON string\n", __func__, __LINE__);
      free(str_without_prefix);
      return JSON_CREATE_FAILED;
    }
    free(str_without_prefix);
  }
  return JSON_OK;
}

json_error_t json_string_array_to_bin_array(cJSON const* const obj, char const key[], UT_array* ut, size_t elm_len) {
  if (obj == NULL || key == NULL || ut == NULL || elm_len == 0) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return JSON_INVALID_PARAMS;
  }

  cJSON* json_item = cJSON_GetObjectItemCaseSensitive(obj, key);
  if (json_item == NULL) {
    printf("[%s:%d] JSON key not found: %s\n", __func__, __LINE__, key);
    return JSON_KEY_NOT_FOUND;
  }

  if (cJSON_IsArray(json_item)) {
    cJSON* current_obj = NULL;
    cJSON_ArrayForEach(current_obj, json_item) {
      char* elm_str = cJSON_GetStringValue(current_obj);
      if (!elm_str) {
        printf("[%s:%d] encountered non-string array member\n", __func__, __LINE__);
        return JSON_ERR;
      }
      byte_t* elm_bin = malloc(elm_len);
      if (!elm_bin) {
        printf("[%s:%d] OOM\n", __func__, __LINE__);
        return JSON_MEMORY_ERROR;
      }
      if (memcmp(elm_str, JSON_HEX_ENCODED_STRING_PREFIX, JSON_HEX_ENCODED_STR_PREFIX_LEN) != 0) {
        printf("[%s:%d] hex string without %s prefix \n", __func__, __LINE__, JSON_HEX_ENCODED_STRING_PREFIX);
        return JSON_NOT_HEX_STRING;
      }
      // convert hex string to binary
      if (hex_2_bin(elm_str, strlen(elm_str), JSON_HEX_ENCODED_STRING_PREFIX, elm_bin, elm_len) ==
          0) {  // 0x prefix needs to be skipped
        utarray_push_back(ut, elm_bin);
        free(elm_bin);
      } else {
        printf("[%s:%d] convert hex string to binary error\n", __func__, __LINE__);
        free(elm_bin);
        return JSON_ERR;
      }
    }
  } else {
    printf("[%s:%d] %s is not an array object\n", __func__, __LINE__, key);
    return JSON_NOT_ARRAY;
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
