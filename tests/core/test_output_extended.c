// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "core/address.h"
#include "core/models/outputs/output_extended.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_output_extended() {
  // create random ED25519 address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_ED25519;
  iota_crypto_randombytes(addr.address, ADDRESS_ED25519_BYTES);

  // create Native Tokens
  byte_t token_id1[NATIVE_TOKEN_ID_BYTES];
  byte_t token_id2[NATIVE_TOKEN_ID_BYTES];
  byte_t token_id3[NATIVE_TOKEN_ID_BYTES];
  iota_crypto_randombytes(token_id1, NATIVE_TOKEN_ID_BYTES);
  iota_crypto_randombytes(token_id2, NATIVE_TOKEN_ID_BYTES);
  iota_crypto_randombytes(token_id3, NATIVE_TOKEN_ID_BYTES);
  native_tokens_t* native_tokens = native_tokens_new();
  native_tokens_add(&native_tokens, token_id1, "111111111");
  native_tokens_add(&native_tokens, token_id2, "222222222");
  native_tokens_add(&native_tokens, token_id3, "333333333");

  // create Extended Output and validate it
  output_extended_t* output = output_extended_new(&addr, 123456789, &native_tokens, NULL);
  TEST_ASSERT_NOT_NULL(output);
  TEST_ASSERT_EQUAL_UINT8(ADDRESS_TYPE_ED25519, output->address->type);
  TEST_ASSERT_EQUAL_MEMORY(addr.address, output->address->address, ADDRESS_NFT_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, output->amount);
  TEST_ASSERT_NOT_NULL(output->native_tokens);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&output->native_tokens));
  TEST_ASSERT_NULL(output->feature_blocks);

  // serialize Extended Output and validate it
  size_t output_extended_buf_len = output_extended_serialize_len(output);
  TEST_ASSERT(output_extended_buf_len != 0);
  byte_t* output_extended_buf = malloc(output_extended_buf_len);
  TEST_ASSERT_NOT_NULL(output_extended_buf);
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, 1) != 0);  // expect serialization fails
  TEST_ASSERT(output_extended_serialize(output, output_extended_buf, output_extended_buf_len) == 0);

  // deserialize Extended Output and validate it
  output_extended_t* deser_output = output_extended_deserialize(output_extended_buf, 1);
  TEST_ASSERT_NULL(deser_output);  // expect deserialization fails
  deser_output = output_extended_deserialize(output_extended_buf, output_extended_buf_len);
  TEST_ASSERT_NOT_NULL(deser_output);
  TEST_ASSERT_EQUAL_MEMORY(deser_output->address, &addr, 1 + ADDRESS_ED25519_BYTES);
  TEST_ASSERT_EQUAL_UINT64(123456789, deser_output->amount);
  TEST_ASSERT_EQUAL_UINT32(3, native_tokens_count(&deser_output->native_tokens));

  output_extended_print(output);

  // clean up
  free(output_extended_buf);
  output_extended_free(output);
  output_extended_free(deser_output);
  native_tokens_free(&native_tokens);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_output_extended);

  return UNITY_END();
}
