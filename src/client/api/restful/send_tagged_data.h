// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_SEND_TAGGED_DATA_H__
#define __CLIENT_API_RESTFUL_SEND_TAGGED_DATA_H__

#include "client/api/restful/send_message.h"
#include "core/utils/byte_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send tagged data message
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] tag The tagged data payload binary tag
 * @param[in] tag_len The length of the binary tag
 * @param[in] data The tagged data payload binary data
 * @param[in] data_len The length of the tagged data payload binary data
 * @param[out] res An error or message ID
 * @return int 0 on success
 */
int send_tagged_data_message(iota_client_conf_t const* conf, byte_t tag[], uint8_t tag_len, byte_t data[],
                             uint32_t data_len, res_send_message_t* res);

#ifdef __cplusplus
}
#endif

#endif
