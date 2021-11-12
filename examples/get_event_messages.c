// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/events/node_event.h"

int main(void) {
  event_client_config_t config = {
      .host = "mqtt.lb-0.h.chrysalis-devnet.iota.cafe", .port = 1883, .client_id = "iota_test_1234", .keepalive = 60};
  event_client_handle_t client = event_init(&config);
  event_subscribe(client, "milestones/latest", 1);
  event_subscribe(client, "messages/referenced", 1);
  event_start(client);
  return 0;
}