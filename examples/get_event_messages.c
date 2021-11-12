// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//#include "client/api/mqtt/sub_milestone_latest.h"
#include "client/network/mqtt/mqtt.h"

int main(void) {
  mqtt_client_config_t event_conf = {
      .host = "mqtt.lb-0.h.chrysalis-devnet.iota.cafe", .port = 1883, .client_id = "iota_test_1234", .keepalive = 60};

  mqtt_client_handle_t client = mqtt_init(&event_conf);
  mqtt_subscribe(client, "milestones/latest", 1);
  mqtt_subscribe(client, "messages/referenced", 1);
  mqtt_start(client);  // This is a blocking call
  return 0;
}