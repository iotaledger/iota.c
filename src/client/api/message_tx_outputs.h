// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_MESSAGE_TX_OUTPUTS_H__
#define __CLIENT_API_MESSAGE_TX_OUTPUTS_H__

#include "cJSON.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

int deser_message_tx_extended_output(cJSON *output_obj, transaction_payload_t *payload_tx);
int deser_message_tx_alias_output(cJSON *output_obj, transaction_payload_t *payload_tx);
int deser_message_tx_foundry_output(cJSON *output_obj, transaction_payload_t *payload_tx);
int deser_message_tx_nft_output(cJSON *output_obj, transaction_payload_t *payload_tx);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_MESSAGE_TX_OUTPUTS_H__
