// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __BENCHMARK_BENCHMARK_CONFIG_H__
#define __BENCHMARK_BENCHMARK_CONFIG_H__

#define USE_HTTPS

#ifdef USE_HTTPS
// Node
#define NODE_HOST "api.alphanet.iotaledger.net"
#define NODE_PORT 443

// Faucet
#define FAUCET_HOST "faucet.alphanet.iotaledger.net"
#define FAUCET_PORT 443

#define IS_HTTPS 1
#else
// Node
#define NODE_HOST "api.alphanet.iotaledger.net"
#define NODE_PORT 80

// Faucet
#define FAUCET_HOST "faucet.alphanet.iotaledger.net"
#define FAUCET_PORT 80

#define IS_HTTPS 0
#endif

#endif
