// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef __CLIENT_API_RESTFUL_SEND_TAGGED_DATA_H__
#define __CLIENT_API_RESTFUL_SEND_TAGGED_DATA_H__

#include "client/api/restful/send_block.h"
#include "core/utils/byte_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send tagged data block
 *
 * @param[in] conf The client endpoint configuration
 * @param[in] ver The protocol version
 * @param[in] tag The binary tag of the tagged data payload
 * @param[in] tag_len The length of the binary tag
 * @param[in] data The binary data of the tagged data payload
 * @param[in] data_len The length of the tagged data payload binary data
 * @param[out] res An error or block ID
 * @return int 0 on success
 */
int send_tagged_data_block(iota_client_conf_t const* conf, uint8_t ver, byte_t tag[], uint8_t tag_len, byte_t data[],
                           uint32_t data_len, res_send_block_t* res);

#ifdef __cplusplus
}
#endif

#endif
