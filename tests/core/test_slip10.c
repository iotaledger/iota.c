#include <stdio.h>
#include <string.h>
#include <unity/unity.h>

#include "core/utils/slip10.h"

typedef struct {
  char *str;
  uint32_t exp_path[32];
  size_t path_len;
  int err;
} test_bip32path_t;

static test_bip32path_t bip32path_set[] = {
    {"", {0}, 1, -1},
    {"m", {0}, 1, -1},
    {"m/0H", {BIP32_HARDENED + 0}, 1, 0},
    {"m/0H/1", {BIP32_HARDENED + 0, 1}, 2, 0},
    {"m/0H/1/2H", {BIP32_HARDENED + 0, 1, BIP32_HARDENED + 2}, 3, 0},
    {"m/0H/1/2H/2", {BIP32_HARDENED + 0, 1, BIP32_HARDENED + 2, 2}, 4, 0},
    {"m/0H/1/2H/2/1000000000", {BIP32_HARDENED + 0, 1, BIP32_HARDENED + 2, 2, 1000000000}, 5, 0},
    {"m/0'", {BIP32_HARDENED + 0}, 1, 0},
    {"m/0'/1", {BIP32_HARDENED + 0, 1}, 2, 0},
    {"m/0'/1/2'", {BIP32_HARDENED + 0, 1, BIP32_HARDENED + 2}, 3, 0},
    {"m/0'/1/2'/2", {BIP32_HARDENED + 0, 1, BIP32_HARDENED + 2, 2}, 4, 0},
    {"m/0'/1/2'/2/1000000000", {BIP32_HARDENED + 0, 1, BIP32_HARDENED + 2, 2, 1000000000}, 5, 0},
    {"m/0/2147483647'/1/2147483646'/2", {0, BIP32_HARDENED + 2147483647, 1, BIP32_HARDENED + 2147483646, 2}, 5, 0},
    {"m/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 16, 0},
    {"m/44'/2147483648", {0}, 1, -2},  // invalid range
    {"m/44'/2147483650'", {0}, 1, -2},
    {"m/44'/-1", {0}, 1, -2},
    {"m/44'//0", {0}, 1, -1},  // invalid path format
    {"/0'/1/2'", {0}, 1, -1},
    {"m/44'/'", {0}, 1, -1},
    {"m/44'/'0", {0}, 1, -1},
    {"m/44'/0h", {0}, 1, -1},
    {"m/44'/0''", {0}, 1, -1},
    {"m/44'/0H'", {0}, 1, -1},
};

void test_bip32path() {
  uint32_t path[32] = {};
  size_t test_cases = sizeof(bip32path_set) / sizeof(test_bip32path_t);
  for (size_t i = 0; i < test_cases; i++) {
    printf("test %s\n", bip32path_set[i].str);
    int ret = slip10_parse_path(bip32path_set[i].str, path);
    TEST_ASSERT(ret == bip32path_set[i].err);
    if (ret == 0) {
      TEST_ASSERT_EQUAL_MEMORY(bip32path_set[i].exp_path, path, bip32path_set[i].path_len);
    }
  }
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_bip32path);

  return UNITY_END();
}
