// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <unity/unity.h>

#include "core/address.h"
#include "core/utils/byte_buffer.h"
#include "crypto/iota_crypto.h"

void setUp(void) {}

void tearDown(void) {}

bool str_start_with(char const prefix[], char const str[]) {
  size_t pre_len = strlen(prefix), str_len = strlen(str);
  return str_len < pre_len ? false : memcmp(prefix, str, pre_len) == 0;
}

void test_ed25519_gen() {
  byte_t exp_addr[] = {0x00, 0x51, 0x55, 0x82, 0xfe, 0x64, 0x8b, 0xf,  0x10, 0xa2, 0xb2,
                       0xa1, 0xb9, 0x1d, 0x75, 0x2,  0x19, 0xc,  0x97, 0x9b, 0xaa, 0xbf,
                       0xee, 0x85, 0xb6, 0xbb, 0xb5, 0x2,  0x6,  0x92, 0xe5, 0x5d, 0x16};
  address_t ed25519_addr = {};
  byte_t seed[32] = {};
  byte_t ed25519_serialized[33] = {};
  char bech32_str[65] = {};
  // convert seed from hex string to binary
  TEST_ASSERT(hex_2_bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", 64, seed, 32) == 0);
  // dump_hex(seed, 32);

  TEST_ASSERT(ed25519_address_from_path(seed, sizeof(seed), "m/44'/4218'/0'/0'/0'", &ed25519_addr) == 0);
  // dump_hex(ed25519_addr.address, 32);
  TEST_ASSERT(address_serialize(&ed25519_addr, ed25519_serialized, sizeof(ed25519_serialized)) == 0);
  // dump_hex(ed25519_serialized, 33);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, ed25519_serialized, address_serialized_len(&ed25519_addr));

  // convert binary address to bech32 with iota HRP
  char const *const exp_iota_bech32 = "iota1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v79tf3l";
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_iota_bech32, bech32_str);
  // printf("bech32 [iota]: %s\n", bech32_str);

  // bech32 to address object
  address_t from_bech32 = {};
  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_alias_gen() {
  // random alias address
  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  iota_crypto_randombytes(alias_addr.address, address_len(&alias_addr));

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&alias_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(str_start_with("iota1p", bech32_str) == true);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);
}

void test_nft_gen() {
  // random alias address
  address_t addr = {};
  addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(addr.address, address_len(&addr));

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(str_start_with("iota1z", bech32_str) == true);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&addr, &from_bech32) == true);
}

void test_serializer() {
  byte_t addr_bin[ADDRESS_MAX_BYTES + 1] = {};
  byte_t addr_ser[ADDRESS_MAX_BYTES + 1] = {};

  address_t addr_obj = {};
  // random address
  iota_crypto_randombytes(addr_bin, ADDRESS_MAX_BYTES);

  // ed25519 serializer
  addr_bin[0] = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(address_deserialize(addr_bin, ADDRESS_ED25519_BYTES + 1, &addr_obj) == 0);
  TEST_ASSERT(addr_obj.type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj.address, ADDRESS_ED25519_BYTES);
  TEST_ASSERT(address_serialize(&addr_obj, addr_ser, address_serialized_len(&addr_obj)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, address_serialized_len(&addr_obj));

  // alias serializer
  addr_bin[0] = ADDRESS_TYPE_ALIAS;
  TEST_ASSERT(address_deserialize(addr_bin, ADDRESS_ALIAS_BYTES + 1, &addr_obj) == 0);
  TEST_ASSERT(addr_obj.type == ADDRESS_TYPE_ALIAS);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj.address, ADDRESS_ALIAS_BYTES);
  TEST_ASSERT(address_serialize(&addr_obj, addr_ser, address_serialized_len(&addr_obj)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, address_serialized_len(&addr_obj));

  // nft serializer
  addr_bin[0] = ADDRESS_TYPE_NFT;
  TEST_ASSERT(address_deserialize(addr_bin, ADDRESS_NFT_BYTES + 1, &addr_obj) == 0);
  TEST_ASSERT(addr_obj.type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj.address, ADDRESS_NFT_BYTES);
  TEST_ASSERT(address_serialize(&addr_obj, addr_ser, address_serialized_len(&addr_obj)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, address_serialized_len(&addr_obj));
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_ed25519_gen);
  RUN_TEST(test_alias_gen);
  RUN_TEST(test_nft_gen);
  RUN_TEST(test_serializer);

  return UNITY_END();
}
