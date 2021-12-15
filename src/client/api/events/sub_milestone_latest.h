// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MILESTONE_LATEST_H__
#define __SUB_MILESTONE_LATEST_H__

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Stores timestamp and index
 *
 */
typedef struct {
  uint64_t timestamp;  ///< The timestamp of latest milestone
  uint32_t index;      ///< The index of latest milestone
} milestone_latest_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Parse milestone latest response
 * @param[in] data Response data to parse
 * @param[out] res Parsed response object
 * @return int 0 If success
 */
int parse_milestone_latest(char *data, milestone_latest_t *res);

#ifdef __cplusplus
}
#endif

#endif