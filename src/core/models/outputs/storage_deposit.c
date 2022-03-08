// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "core/models/outputs/storage_deposit.h"

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

bool storage_deposit_sufficient_output_deposit_check(byte_cost_config_t *config, utxo_output_type_t output_type,
                                                     void *output) {
  if (config == NULL || output == NULL) {
    printf("[%s:%d] invalid parameters\n", __func__, __LINE__);
    return false;
  }

  uint64_t min_storage_deposit = calc_minimum_output_deposit(config, output_type, output);
  uint64_t amount = UINT64_MAX;
  unlock_cond_blk_t *storage_return_cond = NULL;

  switch (output_type) {
    case OUTPUT_SINGLE_OUTPUT:
    case OUTPUT_DUST_ALLOWANCE:
    case OUTPUT_TREASURY:
      printf("[%s:%d] deprecated or unsupported output type\n", __func__, __LINE__);
      return false;
    case OUTPUT_BASIC:
      amount = ((output_basic_t *)output)->amount;
      storage_return_cond = cond_blk_list_get_type(((output_basic_t *)output)->unlock_conditions, UNLOCK_COND_STORAGE);
      break;
    case OUTPUT_ALIAS:
      amount = ((output_alias_t *)output)->amount;
      storage_return_cond = cond_blk_list_get_type(((output_alias_t *)output)->unlock_conditions, UNLOCK_COND_STORAGE);
      break;
    case OUTPUT_FOUNDRY:
      amount = ((output_foundry_t *)output)->amount;
      storage_return_cond =
          cond_blk_list_get_type(((output_foundry_t *)output)->unlock_conditions, UNLOCK_COND_STORAGE);
      break;
    case OUTPUT_NFT:
      amount = ((output_nft_t *)output)->amount;
      storage_return_cond = cond_blk_list_get_type(((output_nft_t *)output)->unlock_conditions, UNLOCK_COND_STORAGE);
      break;
  }

  if (amount < min_storage_deposit) {
    printf("[%s:%d] minimum storage deposit amount must be at least %fMi\n", __func__, __LINE__,
           min_storage_deposit / 1000000.0);
    return false;
  }

  if (storage_return_cond) {
    if (((unlock_cond_storage_t *)(storage_return_cond->block))->amount == 0) {
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

    uint64_t amount_to_storage_deposit_delta = amount - ((unlock_cond_storage_t *)(storage_return_cond->block))->amount;
    if (amount_to_storage_deposit_delta > min_storage_deposit) {
      printf(
          "[%s:%d] output amount must be less than minimum storage deposit amount. Storage Deposit Return Unlock is "
          "meant to be used in microtransactions or transactions where only native tokens are sent.\n",
          __func__, __LINE__);
      return false;
    }
  }

  return true;
}
