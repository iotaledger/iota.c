// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include "core/models/payloads/tagged_data.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_tagged_data() {
  char const* const tag = "HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD";
  byte_t data[2048];
  iota_crypto_randombytes(data, 2048);

  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create(tag, data, sizeof(data));
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT((strlen(tag) + 1) == tagged_data->tag->len);
  TEST_ASSERT_EQUAL_STRING(tag, tagged_data->tag->data);

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
  TEST_ASSERT_EQUAL_STRING(tagged_data->tag->data, deser_tagged_data->tag->data);

  // validate binary data
  TEST_ASSERT(tagged_data->data->len == deser_tagged_data->data->len);
  TEST_ASSERT_EQUAL_STRING(tagged_data->data->data, deser_tagged_data->data->data);

  free(serialized_buf);
  tagged_data_free(tagged_data);
  tagged_data_free(deser_tagged_data);
}

void test_tagged_data_without_tag() {
  char const* const tag = "";
  byte_t data[2048];
  iota_crypto_randombytes(data, 2048);

  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create(tag, data, sizeof(data));
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT(0 == tagged_data->tag->len);
  TEST_ASSERT_NULL(tagged_data->tag->data);

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
  TEST_ASSERT_NULL(deser_tagged_data->tag->data);

  // validate binary data
  TEST_ASSERT(tagged_data->data->len == deser_tagged_data->data->len);
  TEST_ASSERT_EQUAL_STRING(tagged_data->data->data, deser_tagged_data->data->data);

  free(serialized_buf);
  tagged_data_free(tagged_data);
  tagged_data_free(deser_tagged_data);
}

void test_tagged_data_without_data() {
  char const* const tag = "HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD, HELLO WORLD";

  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create(tag, NULL, 0);
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT((strlen(tag) + 1) == tagged_data->tag->len);
  TEST_ASSERT_EQUAL_STRING(tag, tagged_data->tag->data);

  // validate binary data
  TEST_ASSERT(0 == tagged_data->data->len);
  TEST_ASSERT_NULL(tagged_data->data->data);

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
  TEST_ASSERT_EQUAL_STRING(tagged_data->tag->data, deser_tagged_data->tag->data);

  // validate binary data
  TEST_ASSERT(tagged_data->data->len == deser_tagged_data->data->len);
  TEST_ASSERT_NULL(deser_tagged_data->data->data);

  free(serialized_buf);
  tagged_data_free(tagged_data);
  tagged_data_free(deser_tagged_data);
}

void test_tagged_data_empty() {
  char const* const tag = "";

  tagged_data_t* tagged_data = tagged_data_new();
  TEST_ASSERT_NOT_NULL(tagged_data);
  tagged_data_free(tagged_data);

  tagged_data = tagged_data_create(tag, NULL, 0);
  TEST_ASSERT_NOT_NULL(tagged_data);

  // validate tag
  TEST_ASSERT(0 == tagged_data->tag->len);
  TEST_ASSERT_NULL(tagged_data->tag->data);

  // validate binary data
  TEST_ASSERT(0 == tagged_data->data->len);
  TEST_ASSERT_NULL(tagged_data->data->data);

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
  TEST_ASSERT_NULL(deser_tagged_data->tag->data);

  // validate binary data
  TEST_ASSERT(tagged_data->data->len == deser_tagged_data->data->len);
  TEST_ASSERT_NULL(deser_tagged_data->data->data);

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
