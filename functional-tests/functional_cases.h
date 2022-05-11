// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __FUNCATIONAL_TEST_CASES_H__
#define __FUNCATIONAL_TEST_CASES_H__

#include <stdbool.h>
#include <stdint.h>

#include "core/utils/macros.h"
#include "wallet/wallet.h"

/**
 * @brief the test configuration
 *
 */
typedef struct {
  char mnemonic[512];                ///< mnemonic sentence
  uint32_t sender_index;             ///< Index of sender address
  uint32_t receiver_index;           ///< Index of receiver address
  uint32_t coin_type;                ///< SLIP44 coin type
  iota_client_conf_t node_config;    ///< node config
  iota_client_conf_t faucet_config;  ///< faucet config
  bool show_payload;                 ///< True for showing message payloads
  uint16_t delay;                    ///< delay time for checking transaction in secondes
} test_config_t;

/**
 * @brief dynamic test paramters used in test cases
 *
 */
typedef struct {
  address_t sender;                                                ///< A sender address derived from sender_index
  address_t recv;                                                  ///< A receiver address derived from receiver_index
  char basic_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];  ///< A message ID of a basic value transaction
  char milestone_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];  ///< A message ID of a milestone message
  char tagged_msg_id[BIN_TO_HEX_STR_BYTES(IOTA_MESSAGE_ID_BYTES)];     ///< A message ID of a tagged data message
  char output_id[BIN_TO_HEX_STR_BYTES(IOTA_OUTPUT_ID_BYTES)];          ///< An output ID of the sender address
  char tx_id[BIN_TO_HEX_STR_BYTES(IOTA_TRANSACTION_ID_BYTES)];         ///< A transaction ID of an output
  iota_wallet_t* w;
} test_data_t;

/**
 * @brief State of a test case
 *
 */
typedef enum {
  STATE_NOT_SUPPORT = -1,  ///< The test case is not supported
  STATE_NA,                ///< The test cases is not avaliable. test cases is needed or not be tested.
  STATE_NG,                ///< The test cases is not good, needs an investgation.
  STATE_PASS               ///< The test cases is passed
} test_state_e;

/**
 * @brief The list of test IDs
 *
 */
typedef enum {
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
} test_cases_e;

/**
 * @brief A test item
 *
 */
typedef struct {
  test_cases_e id;         ///< the ID of this test case
  char const* const name;  ///< the name or description of this case
  test_state_e st;         ///< the state of the case
} test_item_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief run restfull API tests
 *
 * @param[in] conf The configuration object
 * @param[in, out] params The test paramter object
 * @param[in, out] items The test case object
 * @return int
 */
int restful_api_tests(test_config_t* conf, test_data_t* params, test_item_t* items);

#ifdef __cplusplus
}
#endif

#endif
