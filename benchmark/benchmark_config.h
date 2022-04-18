// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __BENCHMARK_BENCHMARK_CONFIG_H__
#define __BENCHMARK_BENCHMARK_CONFIG_H__

#define USE_HTTPS

#ifdef USE_HTTPS
// Node
#define NODE_HOST "localhost"
#define NODE_PORT 14265

// Faucet
#define FAUCET_HOST "localhost"
#define FAUCET_PORT 8091

#define IS_HTTPS 1
#else
// Node
#define NODE_HOST "localhost"
#define NODE_PORT 14265

// Faucet
#define FAUCET_HOST "localhost"
#define FAUCET_PORT 8091

#define IS_HTTPS 0
#endif

#endif
