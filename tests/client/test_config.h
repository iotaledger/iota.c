// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __TEST_CLIENT_API_CONFIG_H__
#define __TEST_CLIENT_API_CONFIG_H__

// enable or disable test cases use the Tangle network.
// We don't enable it by default but enable it for a local test is recommended.
#define TEST_TANGLE_ENABLE 0

#define TEST_INDEXER_API_PATH "/indexer/v1"

#define USE_HTTPS

#ifdef USE_HTTPS
// Node
#define TEST_NODE_HOST "api.lb-0.h.chrysalis-devnet.iota.cafe"
#define TEST_NODE_PORT 443

// Faucet
#define TEST_FAUCET_HOST "faucet.chrysalis-devnet.iota.cafe"
#define TEST_FAUCET_PORT 443

#define TEST_IS_HTTPS 1
#else
// Node
#define TEST_NODE_HOST "api.lb-0.h.chrysalis-devnet.iota.cafe"
#define TEST_NODE_PORT 80

// Faucet
#define TEST_FAUCET_HOST "faucet.chrysalis-devnet.iota.cafe"
#define TEST_FAUCET_PORT 80

#define TEST_IS_HTTPS 0
#endif

// MQTT
#define TEST_EVENTS_HOST "mqtt.lb-0.h.chrysalis-devnet.iota.cafe"
#define TEST_EVENTS_PORT 1883
#define TEST_EVENTS_CLIENT_ID "iota_test_2"
#define TEST_EVENTS_KEEP_ALIVE 60

#define TEST_TIMEOUT_SECONDS 30

#endif
