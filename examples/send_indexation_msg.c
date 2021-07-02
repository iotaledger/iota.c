// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending an indexation message to the Tangle directly.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "client/api/v1/send_message.h"

int main(int argc, char *argv[]) {
  int err = 0;
  iota_client_conf_t ctx = {.host = "api.lb-0.testnet.chrysalis2.com", .port = 443, .use_tls = true};
  res_send_message_t res = {};

  // send out index
  err = send_indexation_msg(&ctx, "iota.c\xF0\x9F\x80\x84", "Hello from iota.c", &res);

  if (res.is_error) {
    printf("Err response: %s\n", res.u.error->msg);
    res_err_free(res.u.error);
  }

  if (err) {
    printf("send indexation failed\n");
  } else {
    printf("message ID: %s\n", res.u.msg_id);
  }
  return 0;
}