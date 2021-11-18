// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __SUB_MILESTONES_CONFIRMED_H__
#define __SUB_MILESTONES_CONFIRMED_H__

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Stores timestamp and index
 *
 */
typedef struct {
  uint64_t timestamp;
  uint32_t index;
} milestone_confirmed_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates milestone confirmed response object
 * @return res_balance_t*
 */
milestone_confirmed_t *res_milestones_confirmed_new(void);

/**
 * @brief Frees a milestone confirmed object
 * @param[in] res A response object
 */
void res_milestones_confirmed_free(milestone_confirmed_t *res);

/**
 * @brief Parse milestone confirmed response object
 * @param[in] data Data to parse
 * @param[out] res Parsed response object
 * @return 0 if success
 */
int parse_milestones_confirmed(char *data, milestone_confirmed_t *res);

#ifdef __cplusplus
}
#endif

#endif