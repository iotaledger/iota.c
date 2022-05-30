// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/inputs/utxo_input.h"
#include "core/models/outputs/byte_cost_config.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_byte_cost_config_create_new_config() {
  uint16_t byte_cost = (uint16_t)123456;
  uint8_t byte_factor_data = 111;
  uint8_t byte_factor_key = 222;
  uint16_t byte_offset = (IOTA_OUTPUT_ID_BYTES * byte_factor_key) + (IOTA_BLOCK_ID_BYTES * byte_factor_data) +
                         (sizeof(uint32_t) * byte_factor_data) + (sizeof(uint32_t) * byte_factor_data);

  byte_cost_config_t* config = byte_cost_config_new(byte_cost, byte_factor_data, byte_factor_key);

  TEST_ASSERT_EQUAL_UINT16(byte_cost, config->v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(byte_factor_data, config->v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(byte_factor_key, config->v_byte_factor_key);
  TEST_ASSERT_EQUAL_UINT16(byte_offset, config->v_byte_offset);

  byte_cost_config_free(config);
}

void test_byte_cost_config_create_new_default_config() {
  byte_cost_config_t* config = byte_cost_config_default_new();

  TEST_ASSERT_EQUAL_UINT16(500, config->v_byte_cost);
  TEST_ASSERT_EQUAL_UINT8(1, config->v_byte_factor_data);
  TEST_ASSERT_EQUAL_UINT8(10, config->v_byte_factor_key);
  TEST_ASSERT_EQUAL_UINT16(380, config->v_byte_offset);

  byte_cost_config_free(config);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_byte_cost_config_create_new_config);
  RUN_TEST(test_byte_cost_config_create_new_default_config);

  return UNITY_END();
}
