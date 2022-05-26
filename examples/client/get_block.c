// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of getting a block by its ID from the Tangle.
 *
 */

#include <stdio.h>

#include "client/api/restful/get_block.h"

// replace this block ID as needed
// Milestone
#define BLK_ID "c0192ab155b501d2b51d4342b32970360d03835cce84f3b5a8c58e5f0c403b57"
// Tagged Data
//#define BLK_ID "6fc54c980a7a7480d4cb029c64e9a73eb1d4c3a1df40a297b607e1e137322142"
// Transaction
//#define BLK_ID "e95846e997dc6dae80e9a6dea908577a167b5e7c53b9fd802a760486a8c90d0f"

int main(void) {
  iota_client_conf_t ctx = {.host = "localhost", .port = 443, .use_tls = true};

  res_block_t *blk = res_block_new();
  if (!blk) {
    printf("Failed to create a response block object!\n");
    return -1;
  }

  if (get_block_by_id(&ctx, (char const *)BLK_ID, blk) != 0) {
    printf("Retrieving block from a node failed!\n");
    res_block_free(blk);
    return -1;
  }

  if (blk->is_error) {
    printf("API response: %s\n", blk->u.error->msg);
    res_block_free(blk);
    return -1;
  }

  switch (blk->u.blk->payload_type) {
    case CORE_BLOCK_PAYLOAD_MILESTONE:
      printf("Milestone block received:\n");
      core_block_print(blk->u.blk, 0);
      break;
    case CORE_BLOCK_PAYLOAD_TAGGED:
      printf("Tagged Data block received:\n");
      core_block_print(blk->u.blk, 0);
      break;
    case CORE_BLOCK_PAYLOAD_TRANSACTION:
      printf("Transaction block received:\n");
      core_block_print(blk->u.blk, 0);
      break;
    default:
      printf("Unsupported type of a block received!\n");
      break;
  }

  res_block_free(blk);

  return 0;
}
