// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_TX_OUTPUTS_H__
#define __CLIENT_API_TX_OUTPUTS_H__

#include <stdint.h>

#include "cJSON.h"
#include "client/api/message.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/uint256.h"
#include "utarray.h"

typedef struct {
  char id[100];  // TODO: check this length
  uint256_t amount;
} tx_native_tokens_t;

typedef enum {
  UNLOCK_CONDITION_ADDRESS = 0,
  UNLOCK_CONDITION_DUST_DEPOSIT_RETURN = 1,
  UNLOCK_CONDITION_TIMELOCK = 2,
  UNLOCK_CONDITION_EXPIRATION = 3,
  UNLOCK_CONDITION_STATE_CONTROLLER_ADDRESS = 4,
  UNLOCK_CONDITION_GOVERNOR_ADDRESS = 5
} tx_unlock_condition_type_t;

typedef struct {
  char address[API_ADDR_HEX_STR_LEN];
} tx_address_unlock_t;

typedef struct {
  char address[API_ADDR_HEX_STR_LEN];
  uint64_t amount;
} tx_dust_deposit_return_unlock_t;

typedef struct {
  uint32_t milestone_index;
  uint64_t unit_time;
} tx_timelock_unlock_t;

typedef struct {
  char return_address[API_ADDR_HEX_STR_LEN];
  uint32_t milestone_index;
  uint64_t unit_time;
} tx_expiration_unlock_t;

typedef struct {
  char address[API_ADDR_HEX_STR_LEN];
} tx_state_controller_address_unlock_t;

typedef struct {
  char address[API_ADDR_HEX_STR_LEN];
} tx_governor_address_unlock_t;

typedef struct {
  tx_unlock_condition_type_t unlock_condition_type;
  void *unlock_condition;  ///< Pointer to an unlock condition
} tx_unlock_conditions_t;

typedef enum {
  FEATURE_BLOCK_SENDER = 0,
  FEATURE_BLOCK_ISSUER = 1,
  FEATURE_BLOCK_METADATA = 2,
  FEATURE_BLOCK_TAG = 3
} tx_feature_block_type_t;

typedef struct {
  char address[API_ADDR_HEX_STR_LEN];
} tx_sender_block_t;

typedef struct {
  char address[API_ADDR_HEX_STR_LEN];
} tx_issuer_block_t;

typedef struct {
  byte_buf_t *data;
} tx_metadata_block_t;

typedef struct {
  byte_buf_t *tag;
} tx_tag_block_t;

typedef struct {
  tx_feature_block_type_t feature_block_type;
  void *feature_blocks;  ///< Pointer to a feature block
} tx_feature_blocks_t;

typedef struct {
  uint64_t amount;
  UT_array *nativeTokens;
  UT_array *unlockConditions;
  UT_array *featureBlocks;
} tx_extended_output_t;

#ifdef __cplusplus
extern "C" {
#endif

int deser_tx_extended_output(cJSON *essence_obj, payload_tx_t *payload_tx);
int deser_tx_alias_output(cJSON *essence_obj, payload_tx_t *payload_tx);
int deser_tx_foundry_output(cJSON *essence_obj, payload_tx_t *payload_tx);
int deser_tx_nft_output(cJSON *essence_obj, payload_tx_t *payload_tx);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_TX_OUTPUTS_H__
