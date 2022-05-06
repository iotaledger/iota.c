// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __FUNCATIONAL_TEST_CASES_H__
#define __FUNCATIONAL_TEST_CASES_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/utils/macros.h"
#include "wallet/wallet.h"

typedef struct {
  char mnemonic[512];                ///< mnemonic sentance
  uint32_t sender_index;             ///< Index of sender address
  uint32_t receiver_index;           ///< Index of receiver address
  iota_client_conf_t node_config;    ///< node config
  iota_client_conf_t faucet_config;  ///< faucet config
  bool show_payload;                 ///< True for showing message payloads
  uint16_t delay;                    ///< delay time for checking transaction in secondes
} test_config_t;

typedef struct {
  address_t sender;
  address_t recv;
  char basic_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
  char milestone_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
  char tagged_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];
  char output_id[BIN_TO_HEX_STR_BYTES(IOTA_OUTPUT_ID_BYTES)];
  char tx_id[BIN_TO_HEX_STR_BYTES(IOTA_TRANSACTION_ID_BYTES)];
  iota_wallet_t* w;
} test_data_t;

typedef enum{
  STATE_NOT_SUPPORT = -1,
  STATE_NA,
  STATE_NG,
  STATE_PASS
}test_state_e;

typedef enum{
  CORE_GET_NODE_INFO = 0,
  CORE_GET_TIPS,
  // messages
  CORE_POST_BASIC_MSG,
  CORE_POST_TAGGED_MSG,
  CORE_GET_MSG_MILESTONE,
  CORE_GET_MSG_BASIC,
  CORE_GET_MSG_TAGGED,
  CORE_GET_MSG_META_MILESTONE,
  CORE_GET_MSG_META_BASIC,
  CORE_GET_MSG_META_TAGGED,
  CORE_GET_MSG_CHILD_MILESTONE,
  CORE_GET_MSG_CHILD_BASIC,
  CORE_GET_MSG_CHILD_TAGGED,
  // UTXO
  CORE_GET_OUTPUTS,
  CORE_GET_OUTPUTS_METADATA,
  CORE_GET_RECEIPTS,
  CORE_GET_RECEIPTS_MIGRATED,
  CORE_GET_TREASURY,
  CORE_GET_TX_INC_MSG,
  // Milestones
  CORE_GET_MILESTONES,
  CORE_GET_MILESTONES_UTXO,
  CORE_GET_MILESTONES_INDEX,
  CORE_GET_MILESTONES_INDEX_UTXO,
  // Indexer
  INDEXER_GET_BASIC,
  INDEXER_GET_ALIAS,
  INDEXER_GET_ALIAS_ID,
  INDEXER_GET_FOUNDRY,
  INDEXER_GET_FOUNDRY_ID,
  INDEXER_GET_NFT,
  INDEXER_GET_NFT_ID,
  // faucet
  FAUCET_GET_ENQUEUE,
  MAX_TEST_CASE
}test_cases_e;

typedef struct{
  test_cases_e id;
  char const * const name;
  test_state_e st;
} test_item_t;

#ifdef __cplusplus
extern "C" {
#endif

int restful_api_tests(test_config_t* conf, test_data_t* params, test_item_t* items);

#ifdef __cplusplus
}
#endif

#endif
