// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blake2b_data.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

// BLAKE2 hash function
// test vectors: https://github.com/BLAKE2/BLAKE2/tree/master/testvectors
void test_blake2b_hash() {
  uint8_t msg[256] = {};
  uint8_t out_512[64] = {};
  uint8_t out_256[32] = {};

  for (size_t i = 0; i < sizeof(msg); i++) {
    msg[i] = i;
  }

  for (size_t i = 0; i < sizeof(msg); i++) {
    iota_blake2b_sum(msg, i, out_256, sizeof(out_256));
    iota_blake2b_sum(msg, i, out_512, sizeof(out_512));
    TEST_ASSERT_EQUAL_MEMORY(blake2b_256[i], out_256, sizeof(out_256));
    TEST_ASSERT_EQUAL_MEMORY(blake2b_512[i], out_512, sizeof(out_512));
  }
}

// HMAC-SHA-256 and HMAC-SHA-512
// test vectors: https://tools.ietf.org/html/rfc4231#section-4.2
void test_hmacsha() {
  uint8_t tmp_sha256_out[32] = {};
  uint8_t tmp_sha512_out[64] = {};
  // Test case 1
  uint8_t key_1[32];
  // 20-bytes 0x0b
  memset(key_1, 0x0b, 20);
  memset(key_1 + 20, 0x00, 32 - 20);
  // "Hi There"
  uint8_t data_1[] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
  uint8_t exp_sha256_out1[] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
                               0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
                               0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
  uint8_t exp_sha512_out1[] = {0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a,
                               0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0,
                               0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7,
                               0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e,
                               0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54};

  TEST_ASSERT(iota_crypto_hmacsha256(key_1, data_1, sizeof(data_1), tmp_sha256_out) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_sha256_out1, tmp_sha256_out, sizeof(exp_sha256_out1));

  TEST_ASSERT(iota_crypto_hmacsha512(key_1, data_1, sizeof(data_1), tmp_sha512_out) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_sha512_out1, tmp_sha512_out, sizeof(exp_sha512_out1));

  // Test case 2
  // "Jefe"
  uint8_t key_2[32] = {0x4a, 0x65, 0x66, 0x65};
  // "what do ya want for nothing?""
  uint8_t data_2[] = {0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
                      0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f};
  uint8_t exp_sha256_out2[] = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
                               0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7};
  uint8_t exp_sha512_out2[] = {0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b,
                               0x56, 0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27,
                               0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99,
                               0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3,
                               0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37};

  TEST_ASSERT(iota_crypto_hmacsha256(key_2, data_2, sizeof(data_2), tmp_sha256_out) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_sha256_out2, tmp_sha256_out, sizeof(exp_sha256_out2));

  TEST_ASSERT(iota_crypto_hmacsha512(key_2, data_2, sizeof(data_2), tmp_sha512_out) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_sha512_out2, tmp_sha512_out, sizeof(exp_sha512_out2));
}

typedef struct {
  uint8_t sk[64];
  uint8_t signature[64];
  uint8_t* msg;
  size_t msg_len;
} ed25519_vector_t;

static ed25519_vector_t* ed25519_vector_new() {
  ed25519_vector_t* v = malloc(sizeof(ed25519_vector_t));
  if (!v) {
    return NULL;
  }
  memset(v->sk, 0, sizeof(v->sk));
  memset(v->signature, 0, sizeof(v->signature));
  v->msg = NULL;
  v->msg_len = 0;
  return v;
}

static void ed25519_vector_free(ed25519_vector_t* v) {
  if (v) {
    if (v->msg) {
      free(v->msg);
    }
    free(v);
  }
}

static void hex2bin(char const str[], size_t str_len, uint8_t bin[], size_t bin_len) {
  size_t expected_bin_len = str_len / 2;
  char* pos = (char*)str;
  for (size_t i = 0; i < expected_bin_len; i++) {
    sscanf(pos, "%2hhx", &bin[i]);
    pos += 2;
  }
}

static ed25519_vector_t* parsing_vector(char* line) {
  ed25519_vector_t* vector = ed25519_vector_new();
  TEST_ASSERT_NOT_NULL(vector);

  char* pch = strtok(line, ":");
  int post = 0;
  while (pch != NULL) {
    switch (post) {
      case 0:  // sk
        // printf("sk: %s\n", pch);
        hex2bin(pch, 128, vector->sk, sizeof(vector->sk));
        break;
      case 1:  // pk
        // printf("pk: %s\n", pch);
        break;
      case 2:  // msg
        if (strcmp(pch, "NULL") != 0) {
          // printf("mg: %s\n", pch);
          vector->msg_len = strlen(pch) / 2;
          vector->msg = malloc(vector->msg_len);
          hex2bin(pch, strlen(pch), vector->msg, vector->msg_len);
        }
        break;
      case 3:  // signature with msg
        // printf("sg: %s\n", pch);
        hex2bin(pch, 128, vector->signature, sizeof(vector->signature));
        break;
      default:
        break;
    }
    pch = strtok(NULL, ":");
    post++;
  }
  return vector;
}

// ed25519 signature
// test vectors: https://ed25519.cr.yp.to/python/sign.input
void test_ed25519_signature() {
  FILE* fp;
  char line[1024 * 5];
  uint8_t out_signature[64] = {};
  fp = fopen("./ed25519_sign.input", "r");
  if (!fp) {
    return;
  }
  while (fgets(line, sizeof(line), fp) != NULL) {
    ed25519_vector_t* v = parsing_vector(line);
    TEST_ASSERT_NOT_NULL(v);
    iota_crypto_sign(v->sk, v->msg, v->msg_len, out_signature);
    TEST_ASSERT_EQUAL_MEMORY(v->signature, out_signature, sizeof(v->signature));
    ed25519_vector_free(v);
  }
  fclose(fp);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_hmacsha);
  RUN_TEST(test_blake2b_hash);
  RUN_TEST(test_ed25519_signature);

  return UNITY_END();
}