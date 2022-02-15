// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_PAYLOADS_H__
#define __CLIENT_API_JSON_PARSER_PAYLOADS_H__

#include "cJSON.h"
#include "core/models/payloads/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

int milestone_deserialize(cJSON* payload, milestone_t* ms);

// TODO
int json_transaction_deserialize(cJSON* payload, transaction_payload_t* tx);

// TODO
cJSON* json_transaction_serialize(transaction_payload_t* tx);

// TODO
cJSON* json_tagged_serialize(void* tx);

#ifdef __cplusplus
}
#endif

#endif  // __CLIENT_API_JSON_PARSER_PAYLOADS_H__
