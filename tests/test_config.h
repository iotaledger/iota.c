// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __TEST_CLIENT_API_CONFIG_H__
#define __TEST_CLIENT_API_CONFIG_H__

// Test with private tangle or not
// Set to 1 for debugging individual test cases only
#define TEST_TANGLE_ENABLE 0

#define TEST_IS_HTTPS 0
// Node
#define TEST_NODE_HOST "localhost"
#define TEST_NODE_PORT 14265

// Faucet
#define TEST_FAUCET_HOST "localhost"
#define TEST_FAUCET_PORT 14265

// MQTT
#define TEST_EVENTS_HOST "localhost"
#define TEST_EVENTS_PORT 1883
#define TEST_EVENTS_CLIENT_ID "iota_test_2"
#define TEST_EVENTS_KEEP_ALIVE 60

#define TEST_TIMEOUT_SECONDS 30

// Wallet

// using SLIP44_COIN_TYPE_TEST as default coin type
// uncomment one to choose another coin type
// #define NETWORK_TYPE_SHIMMER
// #define NETWORK_TYPE_MAINNET

// predefined coin types
#if defined(NETWORK_TYPE_SHIMMER)
#define SLIP44_COIN_TYPE SLIP44_COIN_TYPE_SHIMMER
#elif defined(NETWORK_TYPE_MAINNET)
#define SLIP44_COIN_TYPE SLIP44_COIN_TYPE_IOTA
#else
#define SLIP44_COIN_TYPE SLIP44_COIN_TYPE_TEST
#endif

#endif
