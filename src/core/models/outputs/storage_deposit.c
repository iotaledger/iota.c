// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/message.h"
#include "core/models/outputs/storage_deposit.h"

// Defines the rent of a single virtual byte denoted in IOTA tokens
#define DEFAULT_BYTE_COST 500
// Defines the multiplier for data fields
#define DEFAULT_BYTE_COST_FACTOR_DATA 1
// Defines the multiplier for fields which can act as keys for lookups
#define DEFAULT_BYTE_COST_FACTOR_KEY 10

static uint64_t calc_minimum_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type, void *output) {
  if (config == NULL || output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return UINT64_MAX;
  }

  uint64_t weighted_bytes = UINT64_MAX;

  switch (output_type) {
    case OUTPUT_SINGLE_OUTPUT:
    case OUTPUT_DUST_ALLOWANCE:
    case OUTPUT_TREASURY:
      printf("[%s:%d] deprecated or unsupported output type\n", __func__, __LINE__);
      return UINT64_MAX;
    case OUTPUT_BASIC:
      weighted_bytes = output_basic_serialize_len(output) * config->v_byte_factor_data;
      break;
    case OUTPUT_ALIAS:
      weighted_bytes = output_alias_serialize_len(output) * config->v_byte_factor_data;
      break;
    case OUTPUT_FOUNDRY:
      weighted_bytes = output_foundry_serialize_len(output) * config->v_byte_factor_data;
      break;
    case OUTPUT_NFT:
      weighted_bytes = output_nft_serialize_len(output) * config->v_byte_factor_data;
      break;
  }

  return config->v_byte_cost * (weighted_bytes + config->v_byte_offset);
}

// Notice, this solution is a trade-off for memory optimization that we don't create the basic output and calculate byte
// cost from it.
static uint64_t basic_address_storage_deposit(byte_cost_config_t *config, address_t *addr) {
  if (config == NULL || addr == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return UINT64_MAX;
  }

  // output serialized length = output type + amount + native tokens + unlock count + block count
  uint64_t output_serialized_len = 12;  // 1 + 8 + 1 + 1
  // address unlock condition = unlock type + address serialized length
  output_serialized_len += 1 + address_serialized_len(addr);

  return config->v_byte_cost * ((output_serialized_len * config->v_byte_factor_data) + config->v_byte_offset);
}

byte_cost_config_t *storage_deposit_new_config(uint16_t byte_cost, uint8_t byte_factor_data, uint8_t byte_factor_key) {
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

byte_cost_config_t *storage_deposit_new_default_config() {
  return storage_deposit_new_config(DEFAULT_BYTE_COST, DEFAULT_BYTE_COST_FACTOR_DATA, DEFAULT_BYTE_COST_FACTOR_KEY);
}

bool storage_deposit_check_sufficient_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type,
                                                     void *output) {
  if (config == NULL || output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  uint64_t min_storage_deposit = calc_minimum_output_deposit(config, output_type, output);
  uint64_t amount = UINT64_MAX;
  unlock_cond_blk_t *dust_return_cond = NULL;

  switch (output_type) {
    case OUTPUT_SINGLE_OUTPUT:
    case OUTPUT_DUST_ALLOWANCE:
    case OUTPUT_TREASURY:
      printf("[%s:%d] deprecated or unsupported output type\n", __func__, __LINE__);
      return false;
    case OUTPUT_BASIC:
      amount = ((output_basic_t *)output)->amount;
      dust_return_cond = cond_blk_list_get_type(((output_basic_t *)output)->unlock_conditions, UNLOCK_COND_DUST);
      break;
    case OUTPUT_ALIAS:
      amount = ((output_alias_t *)output)->amount;
      dust_return_cond = cond_blk_list_get_type(((output_alias_t *)output)->unlock_conditions, UNLOCK_COND_DUST);
      break;
    case OUTPUT_FOUNDRY:
      amount = ((output_foundry_t *)output)->amount;
      dust_return_cond = cond_blk_list_get_type(((output_foundry_t *)output)->unlock_conditions, UNLOCK_COND_DUST);
      break;
    case OUTPUT_NFT:
      amount = ((output_nft_t *)output)->amount;
      dust_return_cond = cond_blk_list_get_type(((output_nft_t *)output)->unlock_conditions, UNLOCK_COND_DUST);
      break;
  }

  if (amount < min_storage_deposit) {
    printf("[%s:%d] minimum storage deposit amount must be at least %fMi\n", __func__, __LINE__,
           min_storage_deposit / 1000000.0);
    return false;
  }

  if (dust_return_cond) {
    if (((unlock_cond_dust_t *)(dust_return_cond->block))->amount == 0) {
      printf("[%s:%d] storage deposit return amount must not be 0\n", __func__, __LINE__);
      return false;
    }

    uint64_t min_storage_deposit_return =
        basic_address_storage_deposit(config, ((unlock_cond_dust_t *)(dust_return_cond->block))->addr);
    if (((unlock_cond_dust_t *)(dust_return_cond->block))->amount < min_storage_deposit_return) {
      printf("[%s:%d] minimum storage deposit return amount must be at least %fMi\n", __func__, __LINE__,
             min_storage_deposit_return / 1000000.0);
      return false;
    }

    uint64_t amount_to_storage_deposit_delta = amount - ((unlock_cond_dust_t *)(dust_return_cond->block))->amount;
    if (amount_to_storage_deposit_delta > min_storage_deposit) {
      printf(
          "[%s:%d] output amount must be less than minimum storage deposit amount. Dust Deposit Return Unlock is meant "
          "to be used in microtransactions or transactions where only native tokens are sent.\n",
          __func__, __LINE__);
      return false;
    }
  }

  return true;
}
