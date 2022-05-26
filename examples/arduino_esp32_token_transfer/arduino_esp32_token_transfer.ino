// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of transfer IOTA tokens.
 *
 */
#include <WiFi.h>
#include <string.h>

#include <iota_client.h>

#define Mi 1000000

// please set your WiFi SSID and Password
char const* const ssid = "xxxxx";
char const* const passwd = "sssss";

// please set the API endpoint of the IOTA node
char const* const node_host = "localhost";
uint16_t const node_port = 14265;
bool const node_use_tls = false;

uint32_t chipId = 0;

// this sentence is for testing only, DO NOT USE IN PRODUCTION
static char const* const test_mnemonic =
    "acoustic trophy damage hint search taste love bicycle foster cradle brown govern endless depend situate athlete "
    "pudding blame question genius transfer van random vast";
// set the index of sender address
uint32_t const sender_addr_index = 0;
// set the index of receiver address
uint32_t const receiver_addr_index = 1;
// set the amount for token transfer
uint64_t const amount = 1;

int token_transfer() {
  // create a wallet instance
  iota_wallet_t* w = wallet_create(test_mnemonic, "", SLIP44_COIN_TYPE_SHIMMER, 0);
  if (!w) {
    printf("Failed to create a wallet object!\n");
    return -1;
  }

  // set the connected node
  if (wallet_set_endpoint(w, node_host, node_port, node_use_tls) != 0) {
    printf("Failed to set a wallet endpoint!\n");
    wallet_destroy(w);
    return -1;
  }

  // update node configuration for this wallet
  if (wallet_update_node_config(w) != 0) {
    printf("Failed to update a node configuration!\n");
    wallet_destroy(w);
    return -1;
  }

  address_t sender, receiver;
  if (wallet_ed25519_address_from_index(w, false, sender_addr_index, &sender) != 0) {
    printf("Failed to generate the sender address from the index!\n");
    wallet_destroy(w);
    return -1;
  }

  if (wallet_ed25519_address_from_index(w, false, receiver_addr_index, &receiver) != 0) {
    printf("Failed to generate the receiver address from the index!\n");
    wallet_destroy(w);
    return -1;
  }

  // convert sender address to bech32 format
  char bech32_sender[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&sender, w->bech32HRP, bech32_sender, sizeof(bech32_sender)) != 0) {
    printf("Failed encoding sender address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }
  // convert sender address to bech32 format
  char bech32_receiver[BIN_TO_HEX_STR_BYTES(ADDRESS_MAX_BYTES)] = {};
  if (address_to_bech32(&receiver, w->bech32HRP, bech32_receiver, sizeof(bech32_receiver)) != 0) {
    printf("Failed encoding receiver address to bech32 format!\n");
    wallet_destroy(w);
    return -1;
  }

  printf("Sender address: %s\n", bech32_sender);
  printf("Receiver address: %s\n", bech32_receiver);
  printf("Amount to send: %" PRIu64 "\n", amount * Mi);

  // transfer tokens
  printf("Sending transaction block to the Tangle...\n");
  res_send_block_t blk_res = {};
  if (wallet_send_basic_outputs(w, 0, 0, &receiver, amount * Mi, &blk_res) != 0) {
    printf("Sending block to the Tangle failed!\n");
    wallet_destroy(w);
    return -1;
  }

  if (blk_res.is_error) {
    printf("Error: %s\n", blk_res.u.error->msg);
    res_err_free(blk_res.u.error);
    wallet_destroy(w);
    return -1;
  }

  printf("Block successfully sent.\n");
  printf("Block ID: %s\n", blk_res.u.blk_id);

  wallet_destroy(w);

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

  delay(10000);
  Serial.printf("ESP32 Chip model = %s Rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("This chip has %d cores\n", ESP.getChipCores());
  Serial.print("Chip ID: ");
  Serial.println(chipId);
  token_transfer();
}
