// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CORE_MODELS_OUTPUT_FEATURES_H__
#define __CORE_MODELS_OUTPUT_FEATURES_H__

#include <stdint.h>

#include "core/address.h"

/*
 * New output features that do not introduce unlocking conditions, but rather add new functionality and add constraints
 * on output creation are grouped under Features. Each output must not contain more than one feature of each type and
 * not all feature types are supported for each output type.
 */

/**
 * @brief all feature types
 *
 */
typedef enum {
  FEAT_SENDER_TYPE = 0,  // Sender feature is used to specify the validated sender of an output.
  FEAT_ISSUER_TYPE,    // Issuer feature is a special case of the sender feature that is only supported by outputs that
                       // implement a UTXO state machine with chain constraint(Alias, NFT).
  FEAT_METADATA_TYPE,  // Metadata feature carries additional binary data for outputs
  FEAT_TAG_TYPE        // Tag feature is used to tag outputs with an index, so they can be retrieved via the Tag not
                       // only their address.
} feature_type_e;

/**
 * @brief A feature object
 *
 */
typedef struct {
  feature_type_e type;  ///< the type of the feature.
  void* obj;            ///< one of the feature objects.
} output_feature_t;

/**
 * @brief Metadata Feature
 *
 * Outputs may carry additional data with them that is interpreted by higher layer applications built on the Tangle. The
 * protocol treats this metadata as pure binary data, it has no effect on the validity of an output except that it
 * increases the required storage deposit. ISC is a great example of a higher layer protocol that makes use of Metadata
 * Feature: smart contract request parameters are encoded in the metadata field of outputs.
 *
 */
typedef struct {
  uint16_t data_len;  ///< the data length of the Metadata
  byte_t* data;       ///< the data of Metadata.
} feature_metadata_t;

/**
 * @brief Tag Feature
 *
 * A Tag Feature makes it possible to tag outputs with an index, so they can be retrieved through an indexer API not
 * only by their address, but also based on the the Tag. The combination of a Tag Feature, a Metadata Feature and a
 * Sender Feature makes it possible to retrieve data associated to an address and stored in outputs that were created by
 * a specific party (Sender) for a specific purpose (Tag).
 *
 */
typedef struct {
  uint8_t tag_len;                  ///< the length of Indexation Tag.
  byte_t tag[MAX_INDEX_TAG_BYTES];  ///< Indexation Tag, max length is 64 bytes.
} feature_tag_t;

/**
 * @brief A list of features
 *
 */
typedef struct feat_list {
  output_feature_t* current;  // point to the current feature
  struct feat_list* next;     // point to the next feature
} feature_list_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief New a Sender feature
 *
 * Identifies the validated sender of the output.
 *
 * @param[in] addr An address object
 * @return output_feature_t*
 */
output_feature_t* feature_sender_new(address_t const* const addr);

/**
 * @brief New an Issuer feature
 *
 * Identifies the validated issuer of the NFT output.
 *
 * @param[in] addr An address object
 * @return output_feature_t*
 */
output_feature_t* feature_issuer_new(address_t const* const addr);

/**
 * @brief New a Metadata feature
 *
 * Defines metadata (arbitrary binary data) that will be stored in the output.
 *
 * @param[in] data The data in binary form
 * @param[in] data_len The length of the data in bytes
 * @return output_feature_t*
 */
output_feature_t* feature_metadata_new(byte_t const data[], uint32_t data_len);

/**
 * @brief New a Tag feature
 *
 * @param[in] tag The Tag in binary form
 * @param[in] tag_len The length of the Tag in bytes
 * @return output_feature_t*
 */
output_feature_t* feature_tag_new(byte_t const tag[], uint8_t tag_len);

/**
 * @brief Get the length of the serialized feature in bytes
 *
 * @param[in] feat A feature object
 * @return size_t
 */
size_t feature_serialize_len(output_feature_t const* const feat);

/**
 * @brief Serialize a feature to binary
 *
 * @param[in] feat A feature object
 * @param[out] buf A buffer holds serialized data
 * @param[in] buf_len The length of buffer
 * @return size_t The bytes written is returned, 0 on errors
 */
size_t feature_serialize(output_feature_t* feat, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize a binary data to a feature object
 *
 * @param[in] buf The feature data in binary
 * @param[in] buf_len The length of the data
 * @return output_feature_t*
 */
output_feature_t* feature_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief free an output feature
 *
 * @param[in] feat A feature object
 */
void feature_free(output_feature_t* feat);

/**
 * @brief Print an output feature object
 *
 * @param[in] feat A feature object
 */
void feature_print(output_feature_t* feat);

/**
 * @brief New an output feature list object
 *
 * @return feature_list_t*
 */
feature_list_t* feature_list_new();

/**
 * @brief Get the element count of the feature list
 *
 * @param[in] list A feature list object
 * @return uint8_t
 */
uint8_t feature_list_len(feature_list_t* list);

/**
 * @brief Get an output feature pointer by a given type
 *
 * @param[in] list A feature list object
 * @param[in] type The type of feature
 * @return output_feature_t*
 */
output_feature_t* feature_list_get_type(feature_list_t* list, feature_type_e type);

/**
 * @brief Get a feature pointer in the list from a given index
 *
 * @param[in] list A feature list object
 * @param[in] index The index of a feature
 * @return output_feature_t* A pointer of the feature
 */
output_feature_t* feature_list_get(feature_list_t* list, uint8_t index);

/**
 * @brief Add a Sender feature to the list
 *
 * @param[in, out] list A feature list
 * @param[in] addr An address of the sender
 * @return int 0 on success
 */
int feature_list_add_sender(feature_list_t** list, address_t const* const addr);

/**
 * @brief Add an Issuer feature to the list
 *
 * @param[in,out] list A feature list
 * @param[in] addr An address of the issuer
 * @return int 0 on success
 */
int feature_list_add_issuer(feature_list_t** list, address_t const* const addr);

/**
 * @brief Add a Metadata to the list
 *
 * @param[in,out] list A feature list
 * @param[in] data A buffer holds the metadata
 * @param[in] data_len The length of the buffer
 * @return int 0 on success
 */
int feature_list_add_metadata(feature_list_t** list, byte_t const data[], uint32_t data_len);

/**
 * @brief Add a Tag feature to the list
 *
 * @param[in,out] list A feature list
 * @param[in] tag A buffer holds the tag
 * @param[in] tag_len The length of the tag
 * @return int 0 on success
 */
int feature_list_add_tag(feature_list_t** list, byte_t const tag[], uint8_t tag_len);

/**
 * @brief Get the expected serialize length of the feature list
 *
 * @param[in] list A feature list
 * @return size_t
 */
size_t feature_list_serialize_len(feature_list_t* list);

/**
 * @brief Sort the list in ascending order based on feature type
 *
 * @param[in] list A feature list
 */
void feature_list_sort(feature_list_t** list);

/**
 * @brief Serialize a feature list to binary data
 *
 * @param[in] list A feature list
 * @param[out] buf A buffer holds serialized data
 * @param[in] buf_len The length of the buffer
 * @return size_t The bytes written to the buffer, 0 on errors
 */
size_t feature_list_serialize(feature_list_t** list, byte_t buf[], size_t buf_len);

/**
 * @brief Deserialize binary data to a feature list object
 *
 * @param[in] buf The buffer holds a serialized data
 * @param[in] buf_len The length of the buffer
 * @return feature_list_t* The deserialized feature list, NULL on errors
 */
feature_list_t* feature_list_deserialize(byte_t buf[], size_t buf_len);

/**
 * @brief Clone feature list object, it should be freed after use.
 *
 * @param[in] list A feature list object for clone
 * @return feature_list_t* A cloned feature list object
 */
feature_list_t* feature_list_clone(feature_list_t const* const list);

/**
 * @brief Print a feature list
 *
 * @param[in] list A feature list
 * @param[in] immutable Flag which indicates if feature is immutable
 * @param[in] indentation Tab indentation when printing feature list
 */
void feature_list_print(feature_list_t* list, bool immutable, uint8_t indentation);

/**
 * @brief free a feature list object
 *
 * @param[in] list A feature list
 */
void feature_list_free(feature_list_t* list);

#ifdef __cplusplus
}
#endif

#endif
