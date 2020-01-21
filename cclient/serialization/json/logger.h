/*
 * Copyright (c) 2018 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

/**
 * @ingroup serialization_json
 *
 * @{
 *
 * @file
 * @brief
 *
 */
#ifndef CCLIENT_SERIALIZATION_JSON_LOGGER_H
#define CCLIENT_SERIALIZATION_JSON_LOGGER_H

#include "utils/logger_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

extern logger_id_t json_logger_id;

/**
 * @brief Initializes logger of json serialization
 *
 * @param[in] level A level of the logger
 *
 */
void logger_init_json_serializer(logger_level_t level);

/**
 * @brief destroys logger of json serialization
 *
 */
void logger_destroy_json_serializer();

#ifdef __cplusplus
}
#endif

#endif  // CCLIENT_SERIALIZATION_JSON_SERIALIZER_H

/** @} */