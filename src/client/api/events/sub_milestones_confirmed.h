// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MILESTONES_CONFIRMED_H__
#define __SUB_MILESTONES_CONFIRMED_H__

#include <stdint.h>

/**
 * @brief Stores timestamp and index
 *
 */
typedef struct {
  uint64_t timestamp;  ///< The timestamp of confirmed milestone
  uint32_t index;      ///< The index of confirmed milestone
} milestone_confirmed_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Parse milestone confirmed response object
 * @param[in] data Response data to parse
 * @param[out] res Parsed response object
 * @return int 0 If success
 */
int parse_milestones_confirmed(char *data, milestone_confirmed_t *res);

#ifdef __cplusplus
}
#endif

#endif