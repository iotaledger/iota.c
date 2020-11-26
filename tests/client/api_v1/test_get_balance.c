#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unity/unity.h>

#include "core/utils/byte_buffer.h"
#include "client/api/v1/get_balance.h"

#define ADDR_HEX "7ed3d67fc7b619e72e588f51fef2379e43e6e9a856635843b3f29aa3a3f1f006"

void test_get_balance() {

    iota_client_conf_t conf = {
            .url = "https://iota-node/",
            .port = 0  // use default port number
    };

    res_balance_t *res = calloc(1, sizeof(res_balance_t));
    byte_t addr[IOTA_ADDRESS_BYTES];

    // test null cases
    TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, NULL, res));
    TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, "", NULL));
    TEST_ASSERT_EQUAL_INT(-1, get_balance(&conf, "", res));

    // test W-OTS
    addr[IOTA_ADDRESS_BYTES-1] = 0;

    // convert hex2bin
    // TEST_ASSERT_EQUAL_INT(0, hex2bin(ADDR_HEX, addr, IOTA_ADDRESS_BYTES));

    // test ed25519
    addr[IOTA_ADDRESS_BYTES-1] = 1;

    // test for success
    // TEST_ASSERT_EQUAL_INT(0, get_balance(addr, res));
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_get_balance);

  return UNITY_END();
}
