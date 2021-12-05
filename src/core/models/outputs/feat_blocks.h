// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_FEAT_BLOCKS_H__
#define __CORE_MODELS_OUTPUT_FEAT_BLOCKS_H__

#include <stdint.h>

#include "core/types.h"
#include "uthash.h"

/**
 * @brief Type of feature blocks
 *
 */
typedef enum {
  FEAT_SENDER_BLOCK = 0,
  FEAT_ISSUER_BLOCK,
  FEAT_DUST_DEP_RET_BLOCK,
  FEAT_TIMELOCK_MS_INDEX_BLOCK,
  FEAT_TIMELOCK_UNIX_BLOCK,
  FEAT_EXPIRATION_MS_INDEX_BLOCK,
  FEAT_EXPIRATION_UNIX_BLOCK,
  FEAT_METADATA_BLOCK,
  FEAT_INDEXATION_BLOCK
} feat_block_t;

/**
 * @brief Sender Blocks
 *
 * Identifies the validated sender of the output
 *
 */
typedef struct {
  void *address;  ///< one of ED25519, Alias, NFT address
  UT_hash_handle hh;
} sender_blks_t;

/**
 * @brief Issuer Blocks
 *
 * Identifies the validated issuer of the alias output
 *
 */
typedef struct {
  void *address;
  UT_hash_handle hh;
} issuer_blks_t;

/**
 * @brief Dust Deposit Return Blocks
 *
 * Defines the amount of IOTAs that have to be returned to Sender
 *
 */
typedef struct ddr_blks {
  uint64_t amount;
  struct ddr_blks *next;
} dust_dep_ret_blks_t;

/**
 * @brief Timelock Milestone Index Blocks
 *
 * Defines a milestone index until which the output can not be unlocked
 *
 */
typedef struct tmi_blks {
  uint32_t ms_index;
  struct tmi_blks *next;
} timelock_ms_idx_blks_t;

/**
 * @brief Timelock Unix Blocks
 *
 * Defines a unix time until which the output can not be unlocked
 *
 */
typedef struct tu_blks {
  uint32_t unix_time;
  struct tu_blks *next;
} timelock_unix_blks_t;

/**
 * @brief Expiration Milestone Index Blocks
 *
 * Defines a milestone index until which only Address is allowed to unlock the output. After the milestone index, only
 * Sender can unlock it
 *
 */
typedef struct emi_blks {
  uint32_t ms_index;
  struct emi_blks *next;
} exp_ms_idx_blks_t;

/**
 * @brief Expiration Unix Blocks
 *
 * Defines a unix time until which only Address is allowed to unlock the output. After the expiration time, only Sender
 * can unlock it
 *
 */
typedef struct eu_blks {
  uint32_t unix_time;
  struct eu_blks *next;
} exp_unix_blks_t;

/**
 * @brief Metadata Blocks
 *
 * Defines metadata (arbitrary binary data) that will be stored in the output
 *
 */
typedef struct metadata_blks {
  uint32_t data_len;
  byte_t *data;
  struct metadata_blks *next;
} metadata_blks_t;

/**
 * @brief Indexation Blocks
 *
 * Defines an indexation tag to which the output will be indexed. Creates an indexation lookup in nodes
 *
 */
typedef struct index_blks {
  uint8_t tag_len;
  byte_t *tag;
  struct index_blks *next;
} indexaction_blks_t;

#endif
