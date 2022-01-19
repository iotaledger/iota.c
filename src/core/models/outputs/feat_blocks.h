// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_FEAT_BLOCKS_H__
#define __CORE_MODELS_OUTPUT_FEAT_BLOCKS_H__

#include <stdint.h>

#include "core/address.h"
#include "core/types.h"
// #include "uthash.h"

/*
 * New output features that do not introduce unlocking conditions, but rather add new functionality and add constraints
 * on output creation are grouped under Feature Blocks. Each Output must not contain more than one feature block of each
 * type and not all block types are supported for each output type.
 */

// Maximum possible length in bytes of a Tag
#define MAX_INDEX_TAG_BYTES 64
// Maximun possible length in bytes of Metadata
#define MAX_METADATA_LGN_BYTES 1024

/**
 * @brief all feature block types
 *
 */
typedef enum {
  FEAT_SENDER_BLOCK = 0,  // Sender block is used to specify the validated sender of an output.
  FEAT_ISSUER_BLOCK,      // Issuer block is a special case of the sender block that is only supported by outputs that
                          // implement a UTXO state machine with chain constraint(Alias, NFT).
  FEAT_METADATA_BLOCK,    // Metadata block carries additional binary data for outputs
  FEAT_TAG_BLOCK          // Tag block is used to tag outputs with an index, so they can be retrieved via the Tag not
                          // only their address.
} feat_block_e;

/**
 * @brief A feature block object
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
 * @brief Tag Blocks
 *
 * Defines an indexation tag to which the output will be indexed. Creates an indexation lookup in nodes
 *
 */
typedef struct tag_blks {
  uint8_t tag_len;                  ///< the length of Indexation Tag.
  byte_t tag[MAX_INDEX_TAG_BYTES];  ///< Indexation Tag, max length is 64 bytes.
} feat_tag_blk_t;

/**
 * @brief A list of feature blocks
 *
 */
typedef struct feat_blk_list {
  feat_block_t* blk;           // point to current feature block
  struct feat_blk_list* next;  // point to next feature block
} feat_blk_list_t;

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief New a Tag feature block
 *
 * @param[in] tag The Tag in binary form
 * @param[in] tag_len The length of the Tag in bytes
 * @return feat_block_t*
 */
feat_block_t* new_feat_blk_tag(byte_t const tag[], uint8_t tag_len);

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
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t feat_blk_serialize(feat_block_t* blk, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a feature block object
 *
 * @param[in] buf The block data in binary
 * @param[in] buf_len The length of the data
 * @return feat_block_t*
 */
feat_block_t* feat_blk_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief free a feature block
 *
 * @param[in] blk A feature block object
 */
void free_feat_blk(feat_block_t* blk);

/**
 * @brief Print a feature block object
 *
 * @param[in] blk A feature block object
 */
void feat_blk_print(feat_block_t* blk);

/**
 * @brief New a feature block list object
 *
 * @return feat_blk_list_t*
 */
feat_blk_list_t* new_feat_blk_list();

/**
 * @brief Get the element count of the feature list
 *
 * @param[in] list A feature list object
 * @return uint8_t
 */
uint8_t feat_blk_list_len(feat_blk_list_t* list);

/**
 * @brief Get a feature block pointer in the list from a given index
 *
 * @param[in] list A feature list object
 * @param[in] index The index of a feature block
 * @return feat_block_t* A pointer of the feature block
 */
feat_block_t* feat_blk_list_get(feat_blk_list_t* list, uint8_t index);

/**
 * @brief Add a Sender feature block to the list
 *
 * @param[in, out] list A feature list
 * @param[in] addr An address of the sender
 * @return int 0 on success
 */
int feat_blk_list_add_sender(feat_blk_list_t** list, address_t const* const addr);

/**
 * @brief Add an Issuer feature block to the list
 *
 * @param[in,out] list A feature list
 * @param[in] addr An address of the issuer
 * @return int 0 on success
 */
int feat_blk_list_add_issuer(feat_blk_list_t** list, address_t const* const addr);

/**
 * @brief Add a Metadata to the list
 *
 * @param[in,out] list A feature list
 * @param[in] data A buffer holds the metadata
 * @param[in] data_len The length of the buffer
 * @return int 0 on success
 */
int feat_blk_list_add_metadata(feat_blk_list_t** list, byte_t const data[], uint32_t data_len);

/**
 * @brief Add a Tag block to the list
 *
 * @param[in,out] list A feature list
 * @param[in] tag A buffer holds the tag
 * @param[in] tag_len The length of the tag
 * @return int 0 on success
 */
int feat_blk_list_add_tag(feat_blk_list_t** list, byte_t const tag[], uint8_t tag_len);

/**
 * @brief Get the expected serialize length of the feature block list
 *
 * @param[in] list A feature list
 * @return size_t
 */
size_t feat_blk_list_serialize_len(feat_blk_list_t* list);

/**
 * @brief Serialize a feature block list to binary data
 *
 * @param[in] list A feature block list
 * @param[out] buf A buffer holds serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t The bytes written to the buffer, 0 on errors
 */
size_t feat_blk_list_serialize(feat_blk_list_t* list, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize binary data to a feature list object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return feat_blk_list_t* The deserialized feature list, NULL on errors
 */
feat_blk_list_t* feat_blk_list_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone feature block list object, it should be freed after use.
 *
 * @param[in] list A feature block list object for clone
 * @return feat_blk_list_t* New feature block list object
 */
feat_blk_list_t* feat_blk_list_clone(feat_blk_list_t const* const list);

/**
 * @brief Print a feature block list
 *
 * @param[in] list A feature block list
 * @param[in] indentation Tab indentation when printing feature block list
 */
void feat_blk_list_print(feat_blk_list_t* list, uint8_t indentation);

/**
 * @brief free a feature block list object
 *
 * @param[in] list A feature block list
 */
void free_feat_blk_list(feat_blk_list_t* list);

#ifdef __cplusplus
}
#endif

#endif
