// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <unity/unity.h>

#include "core/types.h"
#include "core/utils/bech32.h"

static const char *valid_checksum[] = {
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
};

static const char *invalid_checksum[] = {
    " 1nwldj5",
    "\x7f"
    "1axkwrx",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
};

static int my_strncasecmp(const char *s1, const char *s2, size_t n) {
  size_t i = 0;
  while (i < n) {
    char c1 = s1[i];
    char c2 = s2[i];
    if (c1 >= 'A' && c1 <= 'Z') c1 = (c1 - 'A') + 'a';
    if (c2 >= 'A' && c2 <= 'Z') c2 = (c2 - 'A') + 'a';
    if (c1 < c2) return -1;
    if (c1 > c2) return 1;
    if (c1 == 0) return 0;
    ++i;
  }
  return 0;
}

void setUp(void) {}

void tearDown(void) {}

void test_bech32_decode_encode() {
  for (size_t i = 0; i < sizeof(valid_checksum) / sizeof(valid_checksum[0]); ++i) {
    uint8_t data[82] = {};
    char rebuild[92] = {};
    char hrp[84] = {};
    size_t data_len = 0;
    TEST_ASSERT(bech32_decode(hrp, data, &data_len, valid_checksum[i]) == 1);
    TEST_ASSERT(bech32_encode(rebuild, hrp, data, data_len) == 1);
    TEST_ASSERT(my_strncasecmp(rebuild, valid_checksum[i], 92) == 0);
  }

  for (size_t i = 0; i < sizeof(invalid_checksum) / sizeof(invalid_checksum[0]); ++i) {
    uint8_t data[82] = {};
    char hrp[84] = {};
    size_t data_len = 0;
    TEST_ASSERT(bech32_decode(hrp, data, &data_len, invalid_checksum[i]) == 0);
  }
}

void test_bech32_iota_decode_encode() {
  char const *const exp_bech32 = "iot1qxrazekjt3x0720cnvwl9usnf2tmery36hlpl95kpmwedxhss0u5cwx3txe";
  // address verion + address data = 33 bytes
  byte_t exp_addr[33] = {0x01, 0x87, 0xd1, 0x66, 0xd2, 0x5c, 0x4c, 0xff, 0x29, 0xf8, 0x9b,
                         0x1d, 0xf2, 0xf2, 0x13, 0x4a, 0x97, 0xbc, 0x8c, 0x91, 0xd5, 0xfe,
                         0x1f, 0x96, 0x96, 0x0e, 0xdd, 0x96, 0x9a, 0xf0, 0x83, 0xf9, 0x4c};

  // decode
  byte_t tmp_addr[33] = {};
  size_t len = 0;
  TEST_ASSERT(iota_addr_bech32_decode(tmp_addr, &len, "iot", exp_bech32) == 1);
  TEST_ASSERT_EQUAL_UINT32(sizeof(exp_addr), len);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, tmp_addr, sizeof(exp_addr));
  // dump_hex(tmp_addr, len);

  // encode
  char tmp_bech32_addr[64] = {};
  TEST_ASSERT(iota_addr_bech32_encode(tmp_bech32_addr, "iot", exp_addr, sizeof(exp_addr)) == 1);
  TEST_ASSERT_EQUAL_STRING(exp_bech32, tmp_bech32_addr);
  // printf("%s\n", tmp_bech32_addr);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_bech32_decode_encode);
  RUN_TEST(test_bech32_iota_decode_encode);

  return UNITY_END();
}
