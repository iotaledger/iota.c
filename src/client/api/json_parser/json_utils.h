// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_PARSER_JSON_UTILS_H__
#define __CLIENT_API_JSON_PARSER_JSON_UTILS_H__

#include <stdbool.h>
#include <stdint.h>

#include "cJSON.h"
#include "client/api/json_parser/json_keys.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "utarray.h"

// Hex encoded strings in JSON are formatted with 0x prefix
// Example: "0x9cd745ef6800c8e8c80b09174ee4b250b3c43dfa62d7c6a4e61f848febf731a0"
#define JSON_HEX_ENCODED_STRING_PREFIX "0x"
// Length of prefix for encoded strings in JSON
#define JSON_HEX_ENCODED_STR_PREFIX_LEN 2
// Get the hex string with prefix bytes of the given binary
#define JSON_STR_WITH_PREFIX_BYTES(x) (BIN_TO_HEX_STR_BYTES(x) + JSON_HEX_ENCODED_STR_PREFIX_LEN)

typedef enum {
  JSON_OK = 0,
  JSON_INVALID_PARAMS,
  JSON_MEMORY_ERROR,
  JSON_KEY_NOT_FOUND,
  JSON_NOT_HEX_STRING,
  JSON_NOT_STRING,
  JSON_NOT_BOOL,
  JSON_NOT_ARRAY,
  JSON_NOT_NUMBER,
  JSON_NOT_UNSIGNED,
  JSON_CREATE_FAILED,
  JSON_ERR
} json_error_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets the string from a JSON object by key.
 *
 * @param[in] obj A JSON object
 * @param[in] key The key of elememt
 * @param[out] str The string of element
 * @param[in] str_len The max length of string buffer
 * @return json_error_t
 */
json_error_t json_get_string(cJSON const* const obj, char const key[], char str[], size_t str_len);

/**
 * @brief Gets the string with 0x prefix from a JSON object by key.
 *
 * @param[in] obj A JSON object
 * @param[in] key The key of elememt
 * @param[out] str The string of element
 * @param[in] str_len The max length of string buffer
 * @return json_error_t
 */
json_error_t json_get_string_with_prefix(cJSON const* const obj, char const key[], char str[], size_t str_len);

/**
 * @brief Get hex string to binary from a JSON object
 *
 * @param[in] obj A JSON object
 * @param[in] key The key of element
 * @param[out] bin A buffer holds output data
 * @param[in] bin_len The length of buffer
 * @return json_error_t
 */
json_error_t json_get_hex_str_to_bin(cJSON const* const obj, char const key[], byte_t bin[], size_t bin_len);

/**
 * @brief Gets A string from a JSON object by key
 *
 * @param[in] obj A JSON object
 * @param[in] key The key of elememt
 * @param[out] buf A buffer holds the string
 * @return json_error_t
 */
json_error_t json_get_byte_buf_str(cJSON const* const obj, char const key[], byte_buf_t* buf);

/**
 * @brief Gets a boolean value from a JSON object.
 *
 * @param[in] obj A JSON object.
 * @param[in] key A key of a JSON element.
 * @param[out] boolean bool.
 * @return json_error_t
 */
json_error_t json_get_boolean(cJSON const* const obj, char const key[], bool* const boolean);

/**
 * @brief Converts a JSON string array to an utarray.
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of a JSON element
 * @param[out] ut An utarray holds strings
 * @return json_error_t
 */
json_error_t json_string_array_to_utarray(cJSON const* const obj, char const key[], UT_array* ut);

/**
 * @brief Converts a JSON string with 0x prefix array to an utarray.
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of a JSON element
 * @param[out] ut An utarray holds strings
 * @return json_error_t
 */
json_error_t json_string_with_prefix_array_to_utarray(cJSON const* const obj, char const key[], UT_array* ut);

/**
 * @brief Converts utarray object to an array of JSON string
 *
 * @param[in] ut An utarray of strings
 * @param[in] json_obj A JSON object
 * @param[in] obj_name the key of JSON array
 * @return json_error_t
 */
json_error_t utarray_to_json_string_array(UT_array const* const ut, cJSON* const obj, char const* const key);

/**
 * @brief Converts array of JSON strings to utarray of binary data
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of JSON array
 * @param[out] ut An utarray of binary data
 * @param[in] elm_len A length of each element in an utarray
 * @return json_error_t
 */
json_error_t json_string_array_to_bin_array(cJSON const* const obj, char const key[], UT_array* ut, size_t elm_len);

/**
 * @brief Gets an integer from a JSON object.
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of a JSON element
 * @param[out] num An output integer
 * @return json_error_t
 */
json_error_t json_get_int(cJSON const* const obj, char const key[], int* const num);

/**
 * @brief Gets an uint8_t from a JSON object.
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of a JSON element
 * @param[out] num An output uint8_t
 * @return json_error_t
 */
json_error_t json_get_uint8(cJSON const* const obj, char const key[], uint8_t* const num);

/**
 * @brief Gets an uint16_t from a JSON object.
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of a JSON element
 * @param[out] num An output uint16_t
 * @return json_error_t
 */
json_error_t json_get_uint16(cJSON const* const obj, char const key[], uint16_t* const num);

/**
 * @brief Gets an uint32_t from a JSON object.
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of a JSON element
 * @param[out] num An output uint32_t
 * @return json_error_t
 */
json_error_t json_get_uint32(cJSON const* const obj, char const key[], uint32_t* const num);

/**
 * @brief Gets a float from a JSON object
 *
 * @param obj A JSON object
 * @param key The key of a JSON element
 * @param f The output float
 * @return json_error_t
 */
json_error_t json_get_float(cJSON const* const obj, char const key[], float* const f);

#ifdef __cplusplus
}
#endif

#endif
