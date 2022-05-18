// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of getting a node info.
 *
 */

#include <WiFi.h>
#include <string.h>

#include <iota_client.h>

// please set your WiFi SSID and Passward
const char* ssid = "xxxxx";
const char* passwd = "sssss";

// please set the API endpoint of the IOTA node
const char* node_host = "localhost";
const uint16_t node_port = 14265;
const bool node_use_tls = false;

uint32_t chipId = 0;

int fetch_node_info() {
  iota_client_conf_t ctx = {};
  strcpy(ctx.host, node_host);
  ctx.port = node_port;
  ctx.use_tls = node_use_tls;

  res_node_info_t* info = res_node_info_new();
  if (!info) {
    printf("Failed to create a response node info object!\n");
    return -1;
  }

  if (get_node_info(&ctx, info) != 0) {
    printf("Retrieving node info failed!\n");
    res_node_info_free(info);
    return -1;
  }

  if (info->is_error) {
    // got an error message from node.
    printf("Error: %s\n", info->u.error->msg);
  } else {
    node_info_print(info, 0);
  }

  res_node_info_free(info);
  return 0;
}

void setup() {
  Serial.begin(115200);
  delay(10);

  // connecting to WiFi
  WiFi.begin(ssid, passwd);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
}

void loop() {
  for (int i = 0; i < 17; i = i + 8) {
    chipId |= ((ESP.getEfuseMac() >> (40 - i)) & 0xff) << i;
  }

  Serial.printf("ESP32 Chip model = %s Rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("This chip has %d cores\n", ESP.getChipCores());
  Serial.print("Chip ID: ");
  Serial.println(chipId);
  delay(10000);
  fetch_node_info();
}
