// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_CONSTANTS_H__
#define __CORE_CONSTANTS_H__

#include "crypto/constants.h"

// Transaction ID bytes
#define IOTA_TRANSACTION_ID_BYTES 32

// OUTPUT ID bytes = 34 (IOTA_TRANSACTION_ID + OUTPUT INDEX)
#define IOTA_OUTPUT_ID_BYTES (IOTA_TRANSACTION_ID_BYTES + sizeof(uint16_t))

// Message ID length in binary form
#define IOTA_MESSAGE_ID_BYTES 32

#endif
