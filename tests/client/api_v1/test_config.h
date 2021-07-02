// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __TEST_CLIENT_API_CONFIG_H__
#define __TEST_CLIENT_API_CONFIG_H__

// enable or disable test cases use the Tangle network.
// We don't enable it by default but enable it for a local test is recommended.
#define TEST_TANGLE_ENABLE 0
#define USE_HTTPS

#ifdef USE_HTTPS
#define TEST_NODE_HOST "api.lb-0.testnet.chrysalis2.com"
#define TEST_NODE_PORT 443
#define TEST_IS_HTTPS 1
#else
#define TEST_NODE_HOST "chrysalis-nodes.iota.org"
#define TEST_NODE_PORT 80
#define TEST_IS_HTTPS 0
#endif

#endif