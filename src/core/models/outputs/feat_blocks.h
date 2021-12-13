// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_FEAT_BLOCKS_H__
#define __CORE_MODELS_OUTPUT_FEAT_BLOCKS_H__

#include <stdint.h>

#include "core/address.h"
#include "core/types.h"
#include "uthash.h"

/*
 * Feature Blocks represents the feature of the Output.
 * Each Output must not contain more than one feature block of each type
 * and not all block types are supported for each output type.
 */

// Maximum possible length in bytes of an Indexation Tag.
#define MAX_INDEX_TAG_BYTES 64

/**
 * @brief all feature block types
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
} feat_block_e;

/**
 * @brief A feature bock object
 *
 */
typedef struct {
  feat_block_e type;  ///< the type of feature block.
  void* block;        ///< one of feature blocks.
} feat_block_t;

/**
 * @brief Metadata Blocks
 *
 * Defines metadata (arbitrary binary data) that will be stored in the output
 *
 */
typedef struct metadata_blks {
  uint32_t data_len;  ///< the data length of the Metadata, max length is TBD.
  byte_t* data;       ///< the data of Metadata.
} feat_metadata_blk_t;

/**
 * @brief Indexation Blocks
 *
 * Defines an indexation tag to which the output will be indexed. Creates an indexation lookup in nodes
 *
 */
typedef struct index_blks {
  uint8_t tag_len;                  ///< the length of Indexaction Tag.
  byte_t tag[MAX_INDEX_TAG_BYTES];  ///< Indexation Tag, max length is 64 bytes.
} feat_indexaction_blk_t;

/**
 * @brief New a Sender feature block
 *
 * Identifies the validated sender of the output.
 *
 * @param[in] addr An address object
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_sender(address_t const* const addr);

/**
 * @brief New an Issuer feature block
 *
 * Identifies the validated issuer of the NFT output.
 *
 * @param[in] addr An address object
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_issuer(address_t const* const addr);

/**
 * @brief New a Dust Deposit Return feature block
 *
 * Defines the amount of IOTAs that have to be returned to Sender.
 *
 * @param[in] amount Amount of IOTA tokens the consuming transaction
 * should deposit to the address defined in Sender Block.
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_ddr(uint64_t amount);

/**
 * @brief New a Timelock Milestone Index feature block
 *
 * Defines a milestone index until which the output can not be unlocked.
 *
 * @param[in] ms_idx The milestone index starting from which the output can be consumed.
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_tmi(uint32_t ms_idx);

/**
 * @brief New a Timelock Unix feature block
 *
 * Defines a unix time until which the output can not be unlocked.
 *
 * @param[in] time Unix time (seconds since Unix epoch) starting from which the output can be consumed.
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_tu(uint32_t time);

/**
 * @brief New an Expiration Milestone Index feature block
 *
 * Defines a milestone index until which only Address is allowed to unlock the output.
 * After the milestone index, only Sender can unlock it..
 *
 * @param[in] ms_idx Before this milestone index, Address is allowed to unlock the output,
 * after that only the address defined in Sender Block.
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_emi(uint32_t ms_idx);

/**
 * @brief New an Expiration Unix feature block
 *
 * Defines a unix time until which only Address is allowed to unlock the output.
 * After the expiration time, only Sender can unlock it.
 *
 * @param[in] time Before this unix time, Address is allowed to unlock the output,
 * after that only the address defined in Sender Block.
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_eu(uint32_t time);

/**
 * @brief New a Metadata feature block
 *
 * Defines metadata (arbitrary binary data) that will be stored in the output.
 *
 * @param[in] data The data in binary form
 * @param[in] data_len The length of the data in bytes
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_metadata(byte_t const data[], uint32_t data_len);

/**
 * @brief New an Indexaction feature block
 *
 * @param[in] tag The indexaction tag in binary form
 * @param[in] tag_len The length of the indexaction tag in bytes
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_indexaction(byte_t const tag[], uint8_t tag_len);

/**
 * @brief Get the length of the serialized feature block in bytes
 *
 * @param[in] blk A feature block object
 * @return size_t
 */
size_t feat_blk_serialize_len(feat_block_t const* const blk);

/**
 * @brief Serialize a feature block to binary
 *
 * @param[in] blk A feature block object
 * @param[out] buf A buffer holds serialized data
 * @param[in] buf_len The length of buffer
 * @return int 0 on success
 */
int feat_blk_serialize(feat_block_t* blk, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a feature block object
 *
 * @param[in] buf The data in binary
 * @param[in] buf_len The length of data
 * @param[out] blk The output of the featrue block object.
 * @return int
 */
int feat_blk_deserialize(byte_t buf[], size_t buf_len, feat_block_t* blk);

/**
 * @brief free a featrue block
 *
 * @param[in] blk A feature block object
 */
void free_feat_blk(feat_block_t* blk);

#endif
