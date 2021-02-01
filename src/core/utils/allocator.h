// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_UTILS_ALLOCATOR_H__
#define __CORE_UTILS_ALLOCATOR_H__

/**
 * @brief Memory Allocator abstract layer
 *
 */

#ifdef USE_JEMALLOC
#warning "Use jemalloc allocator"
#include "jemalloc/jemalloc.h"
#else
#include <stdlib.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif
