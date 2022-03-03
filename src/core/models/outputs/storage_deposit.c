// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>

#include "core/models/inputs/utxo_input.h"
#include "core/models/message.h"
#include "core/models/outputs/storage_deposit.h"
#include "core/utils/macros.h"

// Defines the rent of a single virtual byte denoted in IOTA tokens
#define DEFAULT_BYTE_COST 500
// Defines the multiplier for data fields
#define DEFAULT_BYTE_COST_FACTOR_DATA 1
// Defines the multiplier for fields which can act as keys for lookups
#define DEFAULT_BYTE_COST_FACTOR_KEY 10

byte_cost_config_t storage_deposit_get_default_config() {
  byte_cost_config_t default_config = {
      .v_byte_cost = DEFAULT_BYTE_COST,
      .v_byte_factor_data = DEFAULT_BYTE_COST_FACTOR_DATA,
      .v_byte_factor_key = DEFAULT_BYTE_COST_FACTOR_KEY,
      .v_byte_offset = 0,
  };

  // size of: output ID + message ID + milestone index + confirmation unix timestamp
  default_config.v_byte_offset = BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES) * DEFAULT_BYTE_COST_FACTOR_KEY +
                                 BIN_TO_HEX_BYTES(IOTA_MESSAGE_ID_BYTES) * DEFAULT_BYTE_COST_FACTOR_DATA +
                                 sizeof(uint64_t) * DEFAULT_BYTE_COST_FACTOR_DATA +
                                 sizeof(uint64_t) * DEFAULT_BYTE_COST_FACTOR_DATA;

  return default_config;
}

uint64_t storage_deposit_calc_min_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type,
                                                 void *output) {
  if (config == NULL || output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return UINT64_MAX;
  }

  uint64_t weighted_bytes = UINT64_MAX;

  switch (output_type) {
    case OUTPUT_SINGLE_OUTPUT:
    case OUTPUT_DUST_ALLOWANCE:
    case OUTPUT_TREASURY:
      printf("[%s:%d] deprecated or unsupported output\n", __func__, __LINE__);
      return UINT64_MAX;
    case OUTPUT_EXTENDED:
      weighted_bytes = output_extended_serialize_len(output) * config->v_byte_factor_data;
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

  return config->v_byte_cost * weighted_bytes + config->v_byte_offset;
}

bool storage_deposit_check_sufficient_output_deposit(byte_cost_config_t *config, utxo_output_type_t output_type,
                                                     void *output) {
  if (config == NULL || output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  uint64_t min_storage_deposit = storage_deposit_calc_min_output_deposit(config, output_type, output);
  uint64_t amount = UINT64_MAX;
  unlock_cond_blk_t *dust_return_cond = NULL;

  switch (output_type) {
    case OUTPUT_SINGLE_OUTPUT:
    case OUTPUT_DUST_ALLOWANCE:
    case OUTPUT_TREASURY:
      printf("[%s:%d] deprecated or unsupported output\n", __func__, __LINE__);
      return UINT64_MAX;
    case OUTPUT_EXTENDED:
      amount = ((output_extended_t *)output)->amount;
      dust_return_cond = cond_blk_list_get_type(((output_extended_t *)output)->unlock_conditions, UNLOCK_COND_DUST);
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
    printf("[%s:%d] minimum storage deposit amount must be at least %" PRIu64 "Mi\n", __func__, __LINE__,
           min_storage_deposit / 1000000);
    return false;
  }

  if (dust_return_cond) {
    uint64_t minimum = amount - min_storage_deposit;
    uint64_t maximum = amount;
    if (((unlock_cond_dust_t *)dust_return_cond)->amount < minimum ||
        ((unlock_cond_dust_t *)dust_return_cond)->amount >= maximum) {
      printf("[%s:%d] invalid storage deposit return amount\n", __func__, __LINE__);
      return false;
    }
  }

  return true;
}
