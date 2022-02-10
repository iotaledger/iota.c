// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_MACROS_H__
#define __CORE_UTILS_MACROS_H__

// Get the hex bytes of the given binary
#define BIN_TO_HEX_BYTES(x) (x * 2)
// Get the hex string bytes of the given binary
#define BIN_TO_HEX_STR_BYTES(x) (BIN_TO_HEX_BYTES(x) + 1)
// Get the string bytes of the given binary
#define BIN_TO_STR_BYTES(x) (x + 1)

#endif