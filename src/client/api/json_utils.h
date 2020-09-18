#ifndef __CLIENT_API_JSON_UTILS_H__
#define __CLIENT_API_JSON_UTILS_H__

#include "cjson/cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets the string from a JSON object by key.
 *
 * @param[in] json_obj A JSON object
 * @param[in] key The key of elememt
 * @param[out] str The string of element
 * @param[in] max The max length of string buffer
 * @return int 0 on success
 */
int json_get_string(cJSON const* const json_obj, char const* const key, char* str, size_t max);

#ifdef __cplusplus
}
#endif

#endif
