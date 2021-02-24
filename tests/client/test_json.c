// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "client/api/json_utils.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_json_string() {
  typedef struct {
    char *data;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"str\": \"hello\"}", JSON_OK},
      {"{\"str\": 100}", JSON_NOT_STRING},
      {"{\"key\": 100}", JSON_KEY_NOT_FOUND},
  };
  char buf[32] = {};

  TEST_ASSERT(json_get_string(NULL, "key", buf, sizeof(buf)) == JSON_INVALID_PARAMS);

  cJSON *json_obj = cJSON_Parse(test_elm[0].data);
  TEST_ASSERT_NOT_NULL(json_obj);
  TEST_ASSERT(json_get_string(json_obj, "key", buf, sizeof(buf)) == JSON_KEY_NOT_FOUND);
  cJSON_Delete(json_obj);
  json_obj = NULL;

  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  for (size_t i = 0; i < cases; i++) {
    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    TEST_ASSERT(json_get_string(json_obj, "str", buf, sizeof(buf)) == test_elm[i].err);
    cJSON_Delete(json_obj);
    json_obj = NULL;
  }
}

void test_json_boolean() {
  typedef struct {
    char *data;
    bool value;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"key\": 100}", 0, JSON_KEY_NOT_FOUND},   {"{\"bool\": \"hello\"}", 0, JSON_NOT_BOOL},
      {"{\"bool\": 100}", 0, JSON_NOT_BOOL},       {"{\"bool\": \"true\"}", 0, JSON_NOT_BOOL},
      {"{\"bool\": \"false\"}", 0, JSON_NOT_BOOL}, {"{\"bool\": true}", 1, JSON_OK},
      {"{\"bool\": false}", 0, JSON_OK},
  };

  TEST_ASSERT(json_get_boolean(NULL, " ", NULL) == JSON_INVALID_PARAMS);

  cJSON *json_obj = NULL;
  bool value = false;
  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  for (size_t i = 0; i < cases; i++) {
    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    json_error_t ret = json_get_boolean(json_obj, "bool", &value);
    TEST_ASSERT(ret == test_elm[i].err);
    // check value
    if (ret == JSON_OK) {
      TEST_ASSERT(value == test_elm[i].value);
    }
    cJSON_Delete(json_obj);
    json_obj = NULL;
  }
}

void test_json_int() {
  typedef struct {
    char *data;
    int value;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"key\": 100}", 0, JSON_KEY_NOT_FOUND},
      {"{\"num\": \"hello\"}", 0, JSON_NOT_NUMBER},
      {"{\"num\": \"true\"}", 0, JSON_NOT_NUMBER},
      {"{\"num\": true}", 1, JSON_NOT_NUMBER},
      {"{\"num\": false}", 0, JSON_NOT_NUMBER},
      {"{\"num\": 100}", 100, JSON_OK},
      {"{\"num\": -100}", -100, JSON_OK},
      {"{\"num\": 2147483646}", INT_MAX - 1, JSON_OK},
      {"{\"num\": -2147483647}", INT_MIN + 1, JSON_OK},
      {"{\"num\": 2147483647}", INT_MAX, JSON_OK},
      {"{\"num\": -2147483648}", INT_MIN, JSON_OK},
      {"{\"num\": 3000000000}", INT_MAX, JSON_OK},
      {"{\"num\": -3000000000}", INT_MIN, JSON_OK},
  };

  TEST_ASSERT(json_get_int(NULL, " ", NULL) == JSON_INVALID_PARAMS);

  cJSON *json_obj = NULL;
  int value = -1;
  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  for (size_t i = 0; i < cases; i++) {
    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    json_error_t ret = json_get_int(json_obj, "num", &value);
    TEST_ASSERT(ret == test_elm[i].err);
    // check value
    if (ret == JSON_OK) {
      TEST_ASSERT_EQUAL_INT32(test_elm[i].value, value);
    }
    cJSON_Delete(json_obj);
    json_obj = NULL;
  }
}

void test_json_uint8() {
  typedef struct {
    char *data;
    uint8_t value;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"key\": 100}", 0, JSON_KEY_NOT_FOUND},   {"{\"num\": \"hello\"}", 0, JSON_NOT_NUMBER},
      {"{\"num\": \"true\"}", 0, JSON_NOT_NUMBER}, {"{\"num\": true}", 1, JSON_NOT_NUMBER},
      {"{\"num\": false}", 0, JSON_NOT_NUMBER},    {"{\"num\": 100}", 100, JSON_OK},
      {"{\"num\": -100}", 0, JSON_NOT_UNSIGNED},   {"{\"num\": 255}", UINT8_MAX, JSON_OK},
      {"{\"num\": 1024}", (uint8_t)1024, JSON_OK},
  };

  TEST_ASSERT(json_get_uint8(NULL, " ", NULL) == JSON_INVALID_PARAMS);

  cJSON *json_obj = NULL;
  uint8_t value = 0;
  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  for (size_t i = 0; i < cases; i++) {
    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    json_error_t ret = json_get_uint8(json_obj, "num", &value);
    TEST_ASSERT(ret == test_elm[i].err);
    // check value
    if (ret == JSON_OK) {
      TEST_ASSERT_EQUAL_UINT8(test_elm[i].value, value);
    }
    cJSON_Delete(json_obj);
    json_obj = NULL;
  }
}

void test_json_uint16() {
  typedef struct {
    char *data;
    uint16_t value;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"key\": 100}", 0, JSON_KEY_NOT_FOUND},      {"{\"num\": \"hello\"}", 0, JSON_NOT_NUMBER},
      {"{\"num\": \"true\"}", 0, JSON_NOT_NUMBER},    {"{\"num\": true}", 1, JSON_NOT_NUMBER},
      {"{\"num\": false}", 0, JSON_NOT_NUMBER},       {"{\"num\": 100}", 100, JSON_OK},
      {"{\"num\": -100}", 0, JSON_NOT_UNSIGNED},      {"{\"num\": 65535}", UINT16_MAX, JSON_OK},
      {"{\"num\": 70000}", (uint16_t)70000, JSON_OK},
  };

  TEST_ASSERT(json_get_uint16(NULL, " ", NULL) == JSON_INVALID_PARAMS);

  cJSON *json_obj = NULL;
  uint16_t value = 0;
  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  for (size_t i = 0; i < cases; i++) {
    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    json_error_t ret = json_get_uint16(json_obj, "num", &value);
    TEST_ASSERT(ret == test_elm[i].err);
    // check value
    if (ret == JSON_OK) {
      TEST_ASSERT_EQUAL_UINT16(test_elm[i].value, value);
    }
    cJSON_Delete(json_obj);
    json_obj = NULL;
  }
}

void test_json_uint32() {
  typedef struct {
    char *data;
    uint32_t value;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"key\": 100}", 0, JSON_KEY_NOT_FOUND},   {"{\"num\": \"hello\"}", 0, JSON_NOT_NUMBER},
      {"{\"num\": \"true\"}", 0, JSON_NOT_NUMBER}, {"{\"num\": true}", 1, JSON_NOT_NUMBER},
      {"{\"num\": false}", 0, JSON_NOT_NUMBER},    {"{\"num\": 100}", 100, JSON_OK},
      {"{\"num\": -100}", 0, JSON_NOT_UNSIGNED},   {"{\"num\": 4294967295}", UINT32_MAX, JSON_OK},
  };

  TEST_ASSERT(json_get_uint32(NULL, " ", NULL) == JSON_INVALID_PARAMS);

  cJSON *json_obj = NULL;
  uint32_t value = 0;
  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  for (size_t i = 0; i < cases; i++) {
    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    json_error_t ret = json_get_uint32(json_obj, "num", &value);
    TEST_ASSERT(ret == test_elm[i].err);
    // check value
    if (ret == JSON_OK) {
      TEST_ASSERT_EQUAL_UINT32(test_elm[i].value, value);
    }
    cJSON_Delete(json_obj);
    json_obj = NULL;
  }
}

void test_json_uint64() {
  typedef struct {
    char *data;
    uint64_t value;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"key\": 100}", 0, JSON_KEY_NOT_FOUND},
      {"{\"num\": \"hello\"}", 0, JSON_NOT_NUMBER},
      {"{\"num\": \"true\"}", 0, JSON_NOT_NUMBER},
      {"{\"num\": true}", 1, JSON_NOT_NUMBER},
      {"{\"num\": false}", 0, JSON_NOT_NUMBER},
      {"{\"num\": 100}", 100, JSON_OK},
      {"{\"num\": -100}", 0, JSON_NOT_UNSIGNED},
      {"{\"num\": 5000000000}", 5000000000, JSON_OK},
      {"{\"num\": 2779530283277762}", 2779530283277762, JSON_OK},
  };

  TEST_ASSERT(json_get_uint64(NULL, " ", NULL) == JSON_INVALID_PARAMS);

  cJSON *json_obj = NULL;
  uint64_t value = 0;
  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  for (size_t i = 0; i < cases; i++) {
    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    json_error_t ret = json_get_uint64(json_obj, "num", &value);
    TEST_ASSERT(ret == test_elm[i].err);
    // check value
    if (ret == JSON_OK) {
      TEST_ASSERT(test_elm[i].value == value);
    }
    cJSON_Delete(json_obj);
    json_obj = NULL;
  }
}

void test_json_str_arr() {
  typedef struct {
    char *data;
    char *value;
    size_t len;
    json_error_t err;
  } json_test_case_t;

  json_test_case_t test_elm[] = {
      {"{\"key\": 100}", NULL, 0, JSON_KEY_NOT_FOUND},
      {"{\"arr\": \"hello\"}", NULL, 0, JSON_NOT_ARRAY},
      {"{\"arr\": \"true\"}", NULL, 0, JSON_NOT_ARRAY},
      {"{\"arr\": true}", NULL, 0, JSON_NOT_ARRAY},
      {"{\"arr\": false}", NULL, 0, JSON_NOT_ARRAY},
      {"{\"arr\": 100}", NULL, 0, JSON_NOT_ARRAY},
      {"{\"arr\":[\"hello\",\"world\"]}", "hello", 2, JSON_OK},
      {"{\"arr\":[\"world\"]}", "world", 1, JSON_OK},
      {"{\"arr\":[]}", NULL, 0, JSON_OK},
  };

  TEST_ASSERT(json_string_array_to_utarray(NULL, " ", NULL) == JSON_INVALID_PARAMS);

  cJSON *json_obj = NULL;
  char *value = NULL;
  size_t cases = sizeof(test_elm) / sizeof(json_test_case_t);
  UT_array *str_arr = NULL;
  for (size_t i = 0; i < cases; i++) {
    utarray_new(str_arr, &ut_str_icd);

    json_obj = cJSON_Parse(test_elm[i].data);
    TEST_ASSERT_NOT_NULL(json_obj);
    json_error_t ret = json_string_array_to_utarray(json_obj, "arr", str_arr);
    TEST_ASSERT(ret == test_elm[i].err);
    // check value
    if (ret == JSON_OK) {
      TEST_ASSERT_EQUAL_UINT32(test_elm[i].len, utarray_len(str_arr));
      if (utarray_len(str_arr) > 0) {
        TEST_ASSERT_EQUAL_MEMORY(test_elm[i].value, *(const char **)utarray_eltptr(str_arr, 0),
                                 strlen(test_elm[i].value));
      }
    }

    cJSON_Delete(json_obj);
    json_obj = NULL;
    utarray_free(str_arr);
    str_arr = NULL;
  }
}

int main(void) {
  UNITY_BEGIN();

  RUN_TEST(test_json_string);
  RUN_TEST(test_json_boolean);
  RUN_TEST(test_json_int);
  RUN_TEST(test_json_uint8);
  RUN_TEST(test_json_uint16);
  RUN_TEST(test_json_uint32);
  RUN_TEST(test_json_uint64);
  RUN_TEST(test_json_str_arr);

  return UNITY_END();
}
