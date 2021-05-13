// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_JSON_UTILS_H__
#define __CLIENT_API_JSON_UTILS_H__

#include <stdbool.h>
#include <stdint.h>

#include "cJSON.h"
#include "utarray.h"

#include "client/api/json_keys.h"
#include "core/utils/byte_buffer.h"

typedef enum {
  JSON_OK = 0,
  JSON_INVALID_PARAMS,
  JSON_KEY_NOT_FOUND,
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
 * @brief Converts utarray object to an array of JSON string
 *
 * @param[in] ut An utarray of strings
 * @param[in] json_obj A JSON object
 * @param[in] obj_name the key of JSON array
 * @return json_error_t
 */
json_error_t utarray_to_json_string_array(UT_array const* const ut, cJSON* const obj, char const* const key);

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
 * @brief Gets an uint64_t from a JSON object.
 *
 * @param[in] obj A JSON object
 * @param[in] key A key of a JSON element
 * @param[out] num An output uint64_t
 * @return json_error_t
 */
json_error_t json_get_uint64(cJSON const* const obj, char const key[], uint64_t* const num);

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
