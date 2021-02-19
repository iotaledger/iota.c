// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <unity/unity.h>

#include "core/address.h"
#include "core/utils/byte_buffer.h"

void test_address_gen() {
  char const* const exp_iot_bech32 = "iot1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v6ffg6n";
  char const* const exp_iota_bech32 = "iota1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v79tf3l";
  byte_t exp_addr[IOTA_ADDRESS_BYTES] = {0x00, 0x51, 0x55, 0x82, 0xfe, 0x64, 0x8b, 0xf,  0x10, 0xa2, 0xb2,
                                         0xa1, 0xb9, 0x1d, 0x75, 0x2,  0x19, 0xc,  0x97, 0x9b, 0xaa, 0xbf,
                                         0xee, 0x85, 0xb6, 0xbb, 0xb5, 0x2,  0x6,  0x92, 0xe5, 0x5d, 0x16};
  byte_t exp_ed_addr[ED25519_ADDRESS_BYTES] = {0x4d, 0xbc, 0x7b, 0x45, 0x32, 0x46, 0x64, 0x20, 0x9a, 0xe5, 0x59,
                                               0xcf, 0xd1, 0x73, 0xc,  0xb,  0xb1, 0x90, 0x5a, 0x7f, 0x83, 0xe6,
                                               0x5d, 0x48, 0x37, 0xa9, 0x87, 0xe2, 0x24, 0xc1, 0xc5, 0x1e};

  byte_t seed[IOTA_SEED_BYTES] = {};
  byte_t addr_from_path[ED25519_ADDRESS_BYTES] = {};
  char bech32_addr[128] = {};
  byte_t addr_with_ver[IOTA_ADDRESS_BYTES] = {};
  byte_t addr_from_bech32[IOTA_ADDRESS_BYTES] = {};

  // convert seed from hex string to binary
  TEST_ASSERT(hex2bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", IOTA_SEED_BYTES * 2, seed,
                      IOTA_SEED_BYTES) == 0);

  TEST_ASSERT(address_from_path(seed, "m/44'/4218'/0'/0'/0'", addr_from_path) == 0);
  // dump_hex(addr_from_path, ED25519_ADDRESS_BYTES);

  // ed25519 address to IOTA address
  addr_with_ver[0] = ADDRESS_VER_ED25519;
  memcpy(addr_with_ver + 1, addr_from_path, ED25519_ADDRESS_BYTES);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, addr_with_ver, IOTA_ADDRESS_BYTES);
  // dump_hex(addr_with_ver, IOTA_ADDRESS_BYTES);

  // convert binary address to bech32 with iot HRP
  TEST_ASSERT(address_2_bech32(addr_with_ver, "iot", bech32_addr) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_iot_bech32, bech32_addr);
  printf("bech32 [iot]: %s\n", bech32_addr);
  // bech32 to binary address
  TEST_ASSERT(address_from_bech32("iot", bech32_addr, addr_from_bech32) == 0);
  TEST_ASSERT_EQUAL_MEMORY(addr_with_ver, addr_from_bech32, IOTA_ADDRESS_BYTES);

  // convert binary address to bech32 with iota HRP
  TEST_ASSERT(address_2_bech32(addr_with_ver, "iota", bech32_addr) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_iota_bech32, bech32_addr);
  printf("bech32 [iota]: %s\n", bech32_addr);
  // bech32 to binary address
  TEST_ASSERT(address_from_bech32("iota", bech32_addr, addr_from_bech32) == 0);
  TEST_ASSERT_EQUAL_MEMORY(addr_with_ver, addr_from_bech32, IOTA_ADDRESS_BYTES);

  // address from ed25519 keypair
  iota_keypair_t seed_keypair = {};
  byte_t ed_addr[ED25519_ADDRESS_BYTES] = {};

  // address from ed25519 public key
  iota_crypto_keypair(seed, &seed_keypair);
  TEST_ASSERT(address_from_ed25519_pub(seed_keypair.pub, ed_addr) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_ed_addr, ed_addr, ED25519_ADDRESS_BYTES);
  // dump_hex(ed_addr, ED25519_ADDRESS_BYTES);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_address_gen);

  return UNITY_END();
}
