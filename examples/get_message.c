// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <time.h>

#include "client/api/restful/get_message.h"

static char const *const mainnet_hrp = "iota";

void hex_ed25519_2_bech32(char hex_ed25519[], char const hrp[], char bech32[]) {
  byte_t tmp_addr[IOTA_ADDRESS_BYTES] = {};
  hex_2_bin(hex_ed25519, strlen(hex_ed25519), tmp_addr + 1, ED25519_ADDRESS_BYTES);
  address_2_bech32(tmp_addr, hrp, bech32);
}

void hex_pub_2_bech32(char pub[], char const hrp[], char bech32[]) {
  byte_t tmp_addr[IOTA_ADDRESS_BYTES] = {};
  byte_t bin_pub[ED_PUBLIC_KEY_BYTES] = {};
  // hex to binary
  hex_2_bin(pub, strlen(pub), bin_pub, sizeof(bin_pub));
  // public key to ed25519 address
  address_from_ed25519_pub(bin_pub, tmp_addr + 1);
  // ed25519 address to bech32 address
  address_2_bech32(tmp_addr, hrp, bech32);
}

void dump_tx_payload(payload_tx_t *tx) {
  char tmp_bech32_addr[128] = {};
  // print out inputs
  printf("%zu inputs:\n", payload_tx_inputs_count(tx));
  for (size_t i = 0; i < payload_tx_inputs_count(tx); i++) {
    uint32_t index = payload_tx_inputs_tx_output_index(tx, i);
    // public key to ed25519 address
    hex_pub_2_bech32(payload_tx_blocks_public_key(tx, index), mainnet_hrp, tmp_bech32_addr);
    // ed25519 address to bech32
    printf("\taddress: %s\n\toutput index: %" PRIu32 "\n", tmp_bech32_addr, index);
  }

  // print out outputs
  printf("%zu outputs:\n", payload_tx_outputs_count(tx));
  for (size_t i = 0; i < payload_tx_outputs_count(tx); i++) {
    // convert ed25519 address to bech32 address, "iota" as the prefix for mainnet.
    hex_ed25519_2_bech32(payload_tx_outputs_address(tx, i), mainnet_hrp, tmp_bech32_addr);
    printf("\taddress: %s\n\tamount: %" PRIu64 "i\n", tmp_bech32_addr, payload_tx_outputs_amount(tx, i));
  }
}

void dump_indexation_payload(payload_index_t *indexation) {
  char data_buffer[128] = {};
  hex_2_bin((char *)indexation->data->data, strlen((char *)indexation->data->data), (byte_t *)data_buffer,
            sizeof(data_buffer));
  printf("Hex: %s\n", indexation->data->data);
  printf("data: %s\n", data_buffer);
}

void dump_milestone_payload(payload_milestone_t *ml) {
  char time_buf[128] = {};
  struct tm *t = localtime((time_t const *)&ml->timestamp);
  strftime(time_buf, sizeof(time_buf), "%a %Y-%m-%d %H:%M:%S", t);
  printf("index: %" PRIu32 ", timestamp: %s\n", ml->index, time_buf);
}

int main(void) {
  // replace this message id as needed
  // milestone
  // char const *const msg_id = "c3addbf9819088fe6e5f2541b277219528e746a539621ac86663816050750703";
  // data
  // char const* const msg_id = "3ac16fe3ff82c89dcf02fc5fecb374077c4e6ee6a6f71309dc57f1e0bc245c6c";
  // tx
  // char const *const msg_id = "f408260482edcb67ef79a679d6a143a36cc5ffb4c4e11c209f0c5654b34bedc4";
  char const *const msg_id = "2a358d46a9474445123d5999d348227ce39bf87fb805bab8c4b49130c2c475dd";

  iota_client_conf_t ctx = {.host = "chrysalis-nodes.iota.org", .port = 443, .use_tls = true};

  res_message_t *msg = res_message_new();
  if (msg) {
    if (get_message_by_id(&ctx, msg_id, msg) == 0) {
      if (msg->is_error) {
        printf("API response: %s\n", msg->u.error->msg);
      } else {
        switch (msg->u.msg->type) {
          case MSG_PAYLOAD_TRANSACTION:
            printf("it's a transaction message\n");
            dump_tx_payload(msg->u.msg->payload);
            break;
          case MSG_PAYLOAD_INDEXATION:
            printf("it's an indexation message\n");
            dump_indexation_payload(msg->u.msg->payload);
            break;
          case MSG_PAYLOAD_MILESTONE:
            printf("it's a milestone message\n");
            dump_milestone_payload(msg->u.msg->payload);
            break;
          case MSG_PAYLOAD_UNKNOW:
          default:
            printf("Unknow message\n");
            break;
        }
      }
    } else {
      printf("get_message_by_id API failed\n");
    }
    res_message_free(msg);
  } else {
    printf("new message response failed\n");
  }

  return 0;
}
