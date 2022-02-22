// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/restful/get_transaction_included_message.h"
#include "client/network/http.h"
#include "core/models/inputs/utxo_input.h"
#include "core/utils/iota_str.h"
#include "core/utils/macros.h"

int get_transaction_included_message_by_id(iota_client_conf_t const *conf, char const tx_id[], res_message_t *res) {
  if (conf == NULL || tx_id == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (strlen(tx_id) != BIN_TO_HEX_BYTES(IOTA_TRANSACTION_ID_BYTES)) {
    printf("[%s:%d]: invalid transaction id length: %zu\n", __func__, __LINE__, strlen(tx_id));
    return -1;
  }

  int ret = -1;

  // compose restful API command
  char cmd_buffer[103] = {0};  // 103 = max size of api path(38) + IOTA_TRANSACTION_ID_HEX_BYTES(64) + 1
  int snprintf_ret = snprintf(cmd_buffer, sizeof(cmd_buffer), "/api/v2/transactions/%s/included-message", tx_id);

  // check if data stored is not more than buffer length
  if (snprintf_ret > (sizeof(cmd_buffer) - 1)) {
    printf("[%s:%d]: http cmd buffer overflow\n", __func__, __LINE__);
    goto done;
  }

  // http client configuration
  http_client_config_t http_conf = {
      .host = conf->host, .path = cmd_buffer, .use_tls = conf->use_tls, .port = conf->port};
  byte_buf_t *http_res = NULL;

  if ((http_res = byte_buf_new()) == NULL) {
    printf("[%s:%d]: OOM\n", __func__, __LINE__);
    goto done;
  }

  // send request via http client
  long status = 0;
  if ((ret = http_client_get(&http_conf, http_res, &status)) == 0) {
    byte_buf2str(http_res);
    // json deserialization
    ret = deser_get_message((char const *const)http_res->data, res);
  }

done:
  // cleanup command
  byte_buf_free(http_res);
  return ret;
}

int deser_get_transaction_included_message(char const *const j_str, res_message_t *res) {
  if (j_str == NULL || res == NULL) {
    printf("[%s:%d] invalid parameter\n", __func__, __LINE__);
    return -1;
  }

  if (deser_get_message(j_str, res) != 0) {
    return -1;
  }

  // only transaction payload is a valid payload for a deserialized message
  if (!res->is_error && res->u.msg->payload_type != CORE_MESSAGE_PAYLOAD_TRANSACTION) {
    return -1;
  }

  return 0;
}
