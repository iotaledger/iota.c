// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "core/address.h"
#include "core/utils/byte_buffer.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

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
  TEST_ASSERT(hex_2_bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", 64, NULL, seed, 32) == 0);
  // dump_hex(seed, 32);

  TEST_ASSERT(ed25519_address_from_path(seed, sizeof(seed), "m/44'/4218'/0'/0'/0'", &ed25519_addr) == 0);
  // dump_hex(ed25519_addr.address, 32);
  size_t ser_len = address_serialize(&ed25519_addr, ed25519_serialized, sizeof(ed25519_serialized));
  TEST_ASSERT(ser_len == address_serialized_len(&ed25519_addr));
  // dump_hex(ed25519_serialized, ser_len);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, ed25519_serialized, ser_len);

  // convert binary address to bech32 with iota HRP
  char const* const exp_iota_bech32 = "iota1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v79tf3l";
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

  // create alias address from output ID
  byte_t output_id[] = "eb962eb4e400b5f0a5534255a721ffcd7b";
  TEST_ASSERT(alias_address_from_output(output_id, sizeof(output_id), &alias_addr) == 0);

  TEST_ASSERT(address_to_bech32(&alias_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(str_start_with("iota1p", bech32_str) == true);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);
}

void test_nft_gen() {
  // random NFT address
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  iota_crypto_randombytes(nft_addr.address, address_len(&nft_addr));

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&nft_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(str_start_with("iota1z", bech32_str) == true);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);

  // create NFT address from output ID
  byte_t output_id[] = "eb962eb4e400b5f0a5534255a721ffcd7b";
  TEST_ASSERT(alias_address_from_output(output_id, sizeof(output_id), &nft_addr) == 0);

  TEST_ASSERT(address_to_bech32(&nft_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(str_start_with("iota1p", bech32_str) == true);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);
}

void test_serializer() {
  byte_t addr_bin[ADDRESS_SERIALIZED_MAX_BYTES] = {};  // random data
  byte_t addr_ser[ADDRESS_SERIALIZED_MAX_BYTES] = {};  // serialized address
  address_t* addr_obj = NULL;                          // deserialized address
  size_t ser_len = 0;                                  // bytes written to serialized buffer

  // random address
  iota_crypto_randombytes(addr_bin, ADDRESS_SERIALIZED_MAX_BYTES);

  // ed25519 serializer
  addr_bin[0] = ADDRESS_TYPE_ED25519;
  // deserialize with insufficient buffer size
  TEST_ASSERT_NULL(address_deserialize(addr_bin, 1));
  // convert a binary to an address object
  addr_obj = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr_obj);
  TEST_ASSERT(addr_obj->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj->address, ED25519_PUBKEY_BYTES);
  // serialize with insufficient buffer size
  TEST_ASSERT(address_serialize(addr_obj, addr_ser, 1) == 0);
  // convert an address object to a binary data
  ser_len = address_serialize(addr_obj, addr_ser, sizeof(addr_ser));
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, ser_len);
  free_address(addr_obj);

  // alias serializer
  addr_bin[0] = ADDRESS_TYPE_ALIAS;
  // convert a binary to an address object
  addr_obj = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr_obj);
  TEST_ASSERT(addr_obj->type == ADDRESS_TYPE_ALIAS);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj->address, ALIAS_ID_BYTES);
  // convert an address object to a binary data
  ser_len = address_serialize(addr_obj, addr_ser, sizeof(addr_ser));
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, ser_len);
  free_address(addr_obj);

  // nft serializer
  addr_bin[0] = ADDRESS_TYPE_NFT;
  // convert a binary to an address object
  addr_obj = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr_obj);
  TEST_ASSERT(addr_obj->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj->address, NFT_ID_BYTES);
  // convert an address object to a binary data
  ser_len = address_serialize(addr_obj, addr_ser, sizeof(addr_ser));
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, ser_len);
  free_address(addr_obj);
}

void test_clone_equal() {
  byte_t addr_bin[ADDRESS_SERIALIZED_MAX_BYTES] = {};  // random data
  iota_crypto_randombytes(addr_bin, ADDRESS_SERIALIZED_MAX_BYTES);
  addr_bin[0] = ADDRESS_TYPE_ED25519;

  address_t* addr1 = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr1);
  address_t* addr2 = address_clone(addr1);
  TEST_ASSERT_NOT_NULL(addr2);
  TEST_ASSERT(address_equal(addr1, addr2) == true);

  iota_crypto_randombytes(addr2->address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT(address_equal(addr1, addr2) == false);

  free_address(addr1);
  free_address(addr2);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_ed25519_gen);
  RUN_TEST(test_alias_gen);
  RUN_TEST(test_nft_gen);
  RUN_TEST(test_serializer);
  RUN_TEST(test_clone_equal);

  return UNITY_END();
}
