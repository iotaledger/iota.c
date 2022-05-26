// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/get_transaction_included_block.h"
#include "client/constants.h"
#include "client/network/http.h"
#include "core/models/inputs/utxo_input.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

int get_transaction_included_block_by_id(iota_client_conf_t const *conf, char const tx_id[], res_block_t *res) {
  if (conf == NULL || tx_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(tx_id) != BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES)) {
    printf("[%s:%d]: invalid transaction id length: %zu\n", __func__, __LINE__, strlen(tx_id));
    return -1;
  }

  int ret = -1;
  byte_buf_t *http_res = NULL;

  iota_str_t *cmd = NULL;
  char const *const cmd_pre = "/transactions/0x";
  char const *const cmd_post = "/included-block";

  cmd = iota_str_reserve(strlen(NODE_API_PATH) + strlen(cmd_pre) + strlen(cmd_post) +
                         BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES) + 1);
  if (cmd == NULL) {
    printf("[%s:%d]: allocate command buffer failed\n", __func__, __LINE__);
    return -1;
  }

  // composing API command
  snprintf(cmd->buf, cmd->cap, "%s%s%s%s", NODE_API_PATH, cmd_pre, tx_id, cmd_post);
  cmd->len = strlen(cmd->buf);

  // http client configuration
  http_client_config_t http_conf = {.host = conf->host, .path = cmd->buf, .use_tls = conf->use_tls, .port = conf->port};

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long status = 0;
  if ((ret = http_client_get(&http_conf, http_res, &status)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_block((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  iota_str_destroy(cmd);
  byte_buf_free(http_res);
  return ret;
}

int deser_get_transaction_included_block(char const *const j_str, res_block_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (deser_get_block(j_str, res) != 0) {
    return -1;
  }

  // only transaction payload is a valid payload for a deserialized block
  if (!res->is_error && res->u.blk->payload_type != CORE_BLOCK_PAYLOAD_TRANSACTION) {
    return -1;
  }

  return 0;
}
