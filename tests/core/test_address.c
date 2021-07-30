// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <unity/unity.h>

#include "core/address.h"
#include "core/utils/byte_buffer.h"

void setUp(void) {}

void tearDown(void) {}

void test_address_gen() {
  char const* const exp_iot_bech32 = "iot1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v6ffg6n";
  char const* const exp_iota_bech32 = "iota1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v79tf3l";
  char const* const exp_hex_addr = "515582FE648B0F10A2B2A1B91D7502190C979BAABFEE85B6BBB5020692E55D16";
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
  char addr_hex_str[IOTA_ADDRESS_HEX_BYTES + 1] = {};

  // convert seed from hex string to binary
  TEST_ASSERT(hex_2_bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", IOTA_SEED_BYTES * 2, seed,
                        IOTA_SEED_BYTES) == 0);
  dump_hex(seed, IOTA_SEED_BYTES);

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
  // bech32 to hex string
  TEST_ASSERT(address_bech32_to_hex("iot", exp_iot_bech32, addr_hex_str, sizeof(addr_hex_str)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_hex_addr, addr_hex_str, sizeof(addr_hex_str));

  // convert binary address to bech32 with iota HRP
  TEST_ASSERT(address_2_bech32(addr_with_ver, "iota", bech32_addr) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_iota_bech32, bech32_addr);
  printf("bech32 [iota]: %s\n", bech32_addr);
  // bech32 to binary address
  TEST_ASSERT(address_from_bech32("iota", bech32_addr, addr_from_bech32) == 0);
  TEST_ASSERT_EQUAL_MEMORY(addr_with_ver, addr_from_bech32, IOTA_ADDRESS_BYTES);
  // bech32 to hex string
  TEST_ASSERT(address_bech32_to_hex("iota", bech32_addr, addr_hex_str, sizeof(addr_hex_str)) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_hex_addr, addr_hex_str, sizeof(addr_hex_str));

  // address from ed25519 keypair
  iota_keypair_t seed_keypair = {};
  byte_t ed_addr[ED25519_ADDRESS_BYTES] = {};

  // address from ed25519 public key
  iota_crypto_keypair(seed, &seed_keypair);
  TEST_ASSERT(address_from_ed25519_pub(seed_keypair.pub, ed_addr) == 0);
  TEST_ASSERT_EQUAL_MEMORY(exp_ed_addr, ed_addr, ED25519_ADDRESS_BYTES);
  // dump_hex(ed_addr, ED25519_ADDRESS_BYTES);
}

//=========Benchmarks========
#define ADDR_NUMS 1000

static int64_t time_in_ms() {
  struct timeval tv_now;
  gettimeofday(&tv_now, NULL);
  return ((int64_t)tv_now.tv_sec * 1000000L + (int64_t)tv_now.tv_usec) / 1000;
}

static int64_t time_in_us() {
  struct timeval tv_now;
  gettimeofday(&tv_now, NULL);
  return (int64_t)tv_now.tv_sec * 1000000L + (int64_t)tv_now.tv_usec;
};

void addr_bench() {
  char path_buf[128] = {};
  byte_t seed[IOTA_SEED_BYTES] = {};
  byte_t ed_addr[IOTA_ADDRESS_BYTES] = {};
  char bech32_addr[IOTA_ADDRESS_HEX_BYTES + 1] = {};
  size_t ret_size = 0;
  static int64_t start_time = 0, time_spent = 0;
  static int64_t min = 0, max = 0, sum = 0;
  random_seed(seed);

  for (size_t idx = 0; idx < ADDR_NUMS; idx++) {
    ret_size = snprintf(path_buf, 128, "m/44'/4218'/0'/0'/%zu'", idx);
    if (ret_size >= 128) {
      path_buf[128 - 1] = '\0';
    }
    ed_addr[0] = 0;
    start_time = time_in_us();
    if (address_from_path(seed, path_buf, ed_addr + 1) == 0) {
      if (address_2_bech32(ed_addr, "iota", bech32_addr) != 0) {
        printf("convert to bech32 failed\n");
        break;
      }
      time_spent = time_in_us() - start_time;
      max = (idx == 0 || time_spent > max) ? time_spent : max;
      min = (idx == 0 || time_spent < min) ? time_spent : min;
      sum += time_spent;
      // printf("%zu: %"PRId64", max %"PRId64", min %"PRId64"\n", idx, time_spent, max, min);
    } else {
      printf("drive from path failed\n");
      break;
    }
  }

  printf("Bench %d address generation\n\tmin(ms)\tmax(ms)\tavg(ms)\ttotal(ms)\n", ADDR_NUMS);
  printf("\t%.3f\t%.3f\t%.3f\t%.3f\n", min / 1000.0, (max / 1000.0), (sum / ADDR_NUMS) / 1000.0, sum / 1000.0);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_address_gen);
  RUN_TEST(addr_bench);

  return UNITY_END();
}
