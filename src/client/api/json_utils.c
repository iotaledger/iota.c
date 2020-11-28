#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client/api/json_utils.h"

int json_get_string(cJSON const* const json_obj, char const key[], char str[], size_t str_len) {
  if (json_obj == NULL || key == NULL || str == NULL) {
    // invalid parameters
    printf("[%s:%d invalid parameters\n", __func__, __LINE__);
    return -1;
  }

  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(json_obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found %s\n", __func__, __LINE__, key);
    return -1;
  }

  if (cJSON_IsString(json_value) && (json_value->valuestring != NULL)) {
    strncpy(str, json_value->valuestring, str_len);
  } else {
    printf("[%s:%d] %s not string\n", __func__, __LINE__, key);
    return -1;
  }
  return 0;
}

int json_get_boolean(cJSON const* const json_obj, char const key[], bool* const boolean) {
  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(json_obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found %s\n", __func__, __LINE__, key);
    return -1;
  }

  if (cJSON_IsBool(json_value)) {
    *boolean = cJSON_IsTrue(json_value);
  } else {
    printf("[%s:%d] %s not boolean\n", __func__, __LINE__, key);
    return -1;
  }
  return 0;
}

int json_get_number(cJSON const* const json_obj, char const key[], double* const number) {
  cJSON* json_value = cJSON_GetObjectItemCaseSensitive(json_obj, key);
  if (json_value == NULL) {
    printf("[%s:%d] JSON key not found %s\n", __func__, __LINE__, key);
    return -1;
  }

  if (cJSON_IsNumber(json_value)) {
    *number = json_value->valuedouble;
  } else {
    printf("[%s:%d] %s not double\n", __func__, __LINE__, key);
    return -1;
  }

  return 0;
}
