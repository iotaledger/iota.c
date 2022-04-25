// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_MACROS_H__
#define __CORE_UTILS_MACROS_H__

#include <stdint.h>
#include <stdio.h>

#include "core/utils/byte_buffer.h"

// Macro for unused function arguments
#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

// Get the hex bytes of the given binary
#define BIN_TO_HEX_BYTES(x) (x * 2)
// Get the hex string bytes of the given binary
#define BIN_TO_HEX_STR_BYTES(x) (BIN_TO_HEX_BYTES(x) + 1)
// Get the string bytes of the given binary
#define BIN_TO_STR_BYTES(x) (x + 1)

/* clang-format off */
/**
 * @brief Returns string representing tabulator indentation
 *
 * @param[in] i Indentation level. The range of i is between 0 and 5.
 */
#define PRINT_INDENTATION(i)   \
  ((i) == 0   ? "\0"           \
   : (i) == 1 ? "\t\0"         \
   : (i) == 2 ? "\t\t\0"       \
   : (i) == 3 ? "\t\t\t\0"     \
   : (i) == 4 ? "\t\t\t\t\0"   \
   : (i) == 5 ? "\t\t\t\t\t\0" \
              : "\0")
/* clang-format on */

#endif
