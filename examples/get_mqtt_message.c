// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include "client/api/mqtt/sub_milestone_latest.h"
#include "client/network/mqtt/mqtt.h"

void callback(res_milestone_latest_t *res) {
  // To Do Handle Error Cases
  printf("index :%d, timestamp : %ld\n", res->u.received_milestone_latest->index,
         res->u.received_milestone_latest->timestamp);
}

int main(void) {
  mqtt_client_config_t mqtt_conf = {
      .host = "mqtt.lb-0.h.chrysalis-devnet.iota.cafe", .port = 1883, .client_id = "iota_test_123", .keepalive = 60};
  mqtt_init(&mqtt_conf);
  sub_milestone_latest(callback);
  mqtt_start(&mqtt_conf);
}