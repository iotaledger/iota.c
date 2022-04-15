// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/byte_cost_config.h"
#include "core/models/inputs/utxo_input.h"

// Defines the rent of a single virtual byte denoted in IOTA tokens
#define DEFAULT_BYTE_COST 500
// Defines the multiplier for data fields
#define DEFAULT_BYTE_COST_FACTOR_DATA 1
// Defines the multiplier for fields which can act as keys for lookups
#define DEFAULT_BYTE_COST_FACTOR_KEY 10

byte_cost_config_t *byte_cost_config_new(uint16_t byte_cost, uint8_t byte_factor_data, uint8_t byte_factor_key) {
  byte_cost_config_t *config = malloc(sizeof(byte_cost_config_t));
  if (!config) {
    printf("[%s:%d] can not create storage config\n", __func__, __LINE__);
    return NULL;
  }

  config->v_byte_cost = byte_cost;
  config->v_byte_factor_data = byte_factor_data;
  config->v_byte_factor_key = byte_factor_key;

  // size of: output ID + message ID + confirmation milestone index + confirmation unix timestamp
  config->v_byte_offset = (IOTA_OUTPUT_ID_BYTES * byte_factor_key) +    // output ID
                          (IOTA_MESSAGE_ID_BYTES * byte_factor_data) +  // message ID
                          (sizeof(uint32_t) * byte_factor_data) +       // confirmation milestone index
                          (sizeof(uint32_t) * byte_factor_data);        // confirmation unix timestamp

  return config;
}

byte_cost_config_t *byte_cost_config_default_new() {
  return byte_cost_config_new(DEFAULT_BYTE_COST, DEFAULT_BYTE_COST_FACTOR_DATA, DEFAULT_BYTE_COST_FACTOR_KEY);
}

void byte_cost_config_free(byte_cost_config_t *config) {
  if (config) {
    free(config);
  }
}

void byte_cost_config_set(byte_cost_config_t *config, uint16_t byte_cost, uint8_t byte_factor_data,
                          uint8_t byte_factor_key) {
  if (config) {
    config->v_byte_cost = byte_cost;
    config->v_byte_factor_data = byte_factor_data;
    config->v_byte_factor_key = byte_factor_key;

    // size of: output ID + message ID + confirmation milestone index + confirmation unix timestamp
    config->v_byte_offset = (IOTA_OUTPUT_ID_BYTES * byte_factor_key) +    // output ID
                            (IOTA_MESSAGE_ID_BYTES * byte_factor_data) +  // message ID
                            (sizeof(uint32_t) * byte_factor_data) +       // confirmation milestone index
                            (sizeof(uint32_t) * byte_factor_data);        // confirmation unix timestamp
  }
}
