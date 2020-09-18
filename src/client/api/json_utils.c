#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client/api/json_utils.h"

int json_get_string(cJSON const* const json_obj, char const* const key, char* str, size_t max) {
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
    strncpy(str, json_value->valuestring, max);
  } else {
    printf("[%s:%d] %s not string\n", __func__, __LINE__, key);
    return -1;
  }
  return 0;
}
