#ifndef __CLIENT_API_JSON_UTILS_H__
#define __CLIENT_API_JSON_UTILS_H__

#include <stdbool.h>

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets the string from a JSON object by key.
 *
 * @param[in] json_obj A JSON object
 * @param[in] key The key of elememt
 * @param[out] str The string of element
 * @param[in] str_len The max length of string buffer
 * @return int 0 on success
 */
int json_get_string(cJSON const* const json_obj, char const key[], char str[], size_t str_len);

/**
 * @brief Gets a boolean value from a JSON object.
 *
 * @param[in] json_obj A JSON object.
 * @param[in] key A key of a JSON element.
 * @param[out] boolean bool.
 * @return int 0 on success
 *
 */
int json_get_boolean(cJSON const* const json_obj, char const key[], bool* const boolean);

/**
 * @brief Gets an integer from a JSON object.
 * @param[in] json_obj A JSON object.
 * @param[in] key A key of a JSON element.
 * @param[out] integer int.
 * @return
 */
int json_get_number(cJSON const* const json_obj, char const key[], double* const number);

#ifdef __cplusplus
}
#endif

#endif
