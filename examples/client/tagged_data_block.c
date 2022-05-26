// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending a data to the Tangle.
 *
 */

#include <stdio.h>
#include <string.h>

#include "client/api/restful/get_block.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/models/payloads/tagged_data.h"
#include "core/utils/iota_str.h"

#define TAG "iota.c\xF0\x9F\xA6\x8B"
#define MESSAGE "Hello world"

int main(void) {
  iota_client_conf_t ctx = {.host = "localhost", .port = 443, .use_tls = true};

  res_send_block_t res = {};

  // send Hello world to the Tangle
  printf("Sending data block to the Tangle...\n");
  if (send_tagged_data_block(&ctx, 2, (byte_t *)TAG, strlen(TAG), (byte_t *)MESSAGE, strlen(MESSAGE), &res) == 0) {
    if (res.is_error) {
      printf("API response: %s\n", res.u.error->msg);
      return -1;
    }
  } else {
    printf("Sending block failed!\n");
    return -1;
  }

  printf("Block successfully sent.\n");
  printf("Block ID: %s\n", res.u.blk_id);

  res_block_t *blk = res_block_new();
  if (!blk) {
    printf("Failed to create a response block object!\n");
    return -1;
  }

  // fetch block from the Tangle
  printf("Fetching block from the Tangle...\n");
  if (get_block_by_id(&ctx, res.u.blk_id, blk) == 0) {
    if (blk->is_error) {
      printf("API response: %s\n", blk->u.error->msg);
      res_block_free(blk);
      return -1;
    }
  } else {
    printf("Fetching block from a node failed!\n");
    res_block_free(blk);
    return -1;
  }

  printf("Block successfully fetched.\n");

  // check if fetched block is Tagged Data block
  if (blk->u.blk->payload_type != CORE_BLOCK_PAYLOAD_TAGGED) {
    printf("Fetched block is not a Tagged Data block!\n");
    res_block_free(blk);
    return -1;
  }

  // Convert byte arrays to a strings
  if (!byte_buf2str(((tagged_data_payload_t *)blk->u.blk->payload)->tag)) {
    printf("Failed to convert byte array to a string!\n");
    res_block_free(blk);
    return -1;
  }
  if (!byte_buf2str(((tagged_data_payload_t *)blk->u.blk->payload)->data)) {
    printf("Failed to convert byte array to a string!\n");
    res_block_free(blk);
    return -1;
  }

  // print fetched block
  printf("Tagged Data:\n");
  printf("\tTag: %s\n", ((tagged_data_payload_t *)blk->u.blk->payload)->tag->data);
  printf("\tData: %s\n", ((tagged_data_payload_t *)blk->u.blk->payload)->data->data);

  // clean up resources
  res_block_free(blk);

  return 0;
}
