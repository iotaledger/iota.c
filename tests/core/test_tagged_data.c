// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "core/models/payloads/tagged_data.h"
#include "core/utils/macros.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

#define TAG_LEN 64
#define DATA_LEN 2048
char const* const tag_str = "HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD!";

void setUp(void) {}

void tearDown(void) {}

void test_tagged_data() {
  byte_t data[DATA_LEN];
  iota_crypto_randombytes(data, DATA_LEN);

  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create((byte_t*)tag_str, TAG_LEN, data, DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT(TAG_LEN == tagged_data->tag->len);
  TEST_ASSERT_EQUAL_MEMORY((byte_t*)tag_str, tagged_data->tag->data, TAG_LEN);

  // validate binary data
  TEST_ASSERT(sizeof(data) == tagged_data->data->len);
  TEST_ASSERT_EQUAL_MEMORY(data, tagged_data->data->data, sizeof(data));

  // serialization
  size_t serialized_len = tagged_data_serialize_len(tagged_data);
  byte_t* serialized_buf = malloc(serialized_len);
  size_t actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len - 1);
  TEST_ASSERT_EQUAL_INT(0, actual_len);  // expect serialization fails
  actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len);
  TEST_ASSERT(serialized_len == actual_len);

  // deserialization
  tagged_data_t* deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len - 1);
  TEST_ASSERT_NULL(deser_tagged_data);  // expect deserialization fails
  deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len);
  TEST_ASSERT_NOT_NULL(deser_tagged_data);

  // check serialization and deserialization
  // validate tag
  TEST_ASSERT(tagged_data->tag->len == deser_tagged_data->tag->len);
  TEST_ASSERT_EQUAL_MEMORY(tagged_data->tag->data, deser_tagged_data->tag->data, tagged_data->tag->len);

  // validate binary data
  TEST_ASSERT(tagged_data->data->len == deser_tagged_data->data->len);
  TEST_ASSERT_EQUAL_MEMORY(tagged_data->data->data, deser_tagged_data->data->data, tagged_data->data->len);

  // print tagged data payload
  tagged_data_print(tagged_data, 0);

  free(serialized_buf);
  tagged_data_free(tagged_data);
  tagged_data_free(deser_tagged_data);
}

void test_tagged_data_without_tag() {
  char const* const tag = "";
  byte_t data[DATA_LEN];
  iota_crypto_randombytes(data, DATA_LEN);

  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create((byte_t*)tag, 0, data, DATA_LEN);
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT_NULL(tagged_data->tag);

  // validate binary data
  TEST_ASSERT(sizeof(data) == tagged_data->data->len);
  TEST_ASSERT_EQUAL_MEMORY(data, tagged_data->data->data, DATA_LEN);

  // serialization
  size_t serialized_len = tagged_data_serialize_len(tagged_data);
  byte_t* serialized_buf = malloc(serialized_len);
  size_t actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len - 1);
  TEST_ASSERT_EQUAL_INT(0, actual_len);  // expect serialization fails
  actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len);
  TEST_ASSERT(serialized_len == actual_len);

  // deserialization
  tagged_data_t* deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len - 1);
  TEST_ASSERT_NULL(deser_tagged_data);  // expect deserialization fails
  deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len);
  TEST_ASSERT_NOT_NULL(deser_tagged_data);

  // check serialization and deserialization
  // validate tag
  TEST_ASSERT_NULL(deser_tagged_data->tag);

  // validate binary data
  TEST_ASSERT(tagged_data->data->len == deser_tagged_data->data->len);
  TEST_ASSERT_EQUAL_MEMORY(tagged_data->data->data, deser_tagged_data->data->data, tagged_data->data->len);

  // print tagged data payload
  tagged_data_print(tagged_data, 0);

  free(serialized_buf);
  tagged_data_free(tagged_data);
  tagged_data_free(deser_tagged_data);
}

void test_tagged_data_without_data() {
  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create((byte_t*)tag_str, TAG_LEN, NULL, 0);
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT(TAG_LEN == tagged_data->tag->len);
  TEST_ASSERT_EQUAL_MEMORY((byte_t*)tag_str, tagged_data->tag->data, TAG_LEN);

  // validate binary data
  TEST_ASSERT_NULL(tagged_data->data);

  // serialization
  size_t serialized_len = tagged_data_serialize_len(tagged_data);
  byte_t* serialized_buf = malloc(serialized_len);
  size_t actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len - 1);
  TEST_ASSERT_EQUAL_INT(0, actual_len);  // expect serialization fails
  actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len);
  TEST_ASSERT(serialized_len == actual_len);

  // deserialization
  tagged_data_t* deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len - 1);
  TEST_ASSERT_NULL(deser_tagged_data);  // expect deserialization fails
  deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len);
  TEST_ASSERT_NOT_NULL(deser_tagged_data);

  // check serialization and deserialization
  // validate tag
  TEST_ASSERT(tagged_data->tag->len == deser_tagged_data->tag->len);
  TEST_ASSERT_EQUAL_MEMORY(tagged_data->tag->data, deser_tagged_data->tag->data, tagged_data->tag->len);

  // validate binary data
  TEST_ASSERT_NULL(deser_tagged_data->data);

  // print tagged data payload
  tagged_data_print(tagged_data, 0);

  free(serialized_buf);
  tagged_data_free(tagged_data);
  tagged_data_free(deser_tagged_data);
}

void test_tagged_data_empty() {
  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create((byte_t*)tag_str, TAG_LEN, NULL, 0);
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT(TAG_LEN == tagged_data->tag->len);
  TEST_ASSERT_EQUAL_MEMORY((byte_t*)tag_str, tagged_data->tag->data, TAG_LEN);

  // validate binary data
  TEST_ASSERT_NULL(tagged_data->data);

  // serialization
  size_t serialized_len = tagged_data_serialize_len(tagged_data);
  byte_t* serialized_buf = malloc(serialized_len);
  size_t actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len - 1);
  TEST_ASSERT_EQUAL_INT(0, actual_len);  // expect serialization fails
  actual_len = tagged_data_serialize(tagged_data, serialized_buf, serialized_len);
  TEST_ASSERT(serialized_len == actual_len);

  // deserialization
  tagged_data_t* deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len - 1);
  TEST_ASSERT_NULL(deser_tagged_data);  // expect deserialization fails
  deser_tagged_data = tagged_data_deserialize(serialized_buf, serialized_len);
  TEST_ASSERT_NOT_NULL(deser_tagged_data);

  // check serialization and deserialization
  // validate tag
  TEST_ASSERT(tagged_data->tag->len == deser_tagged_data->tag->len);
  TEST_ASSERT_EQUAL_MEMORY(tagged_data->tag->data, deser_tagged_data->tag->data, tagged_data->tag->len);

  // validate binary data
  TEST_ASSERT_NULL(deser_tagged_data->data);

  // print tagged data payload
  tagged_data_print(tagged_data, 0);

  free(serialized_buf);
  tagged_data_free(tagged_data);
  tagged_data_free(deser_tagged_data);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_tagged_data);
  RUN_TEST(test_tagged_data_without_tag);
  RUN_TEST(test_tagged_data_without_data);
  RUN_TEST(test_tagged_data_empty);

  return UNITY_END();
}
