// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * @brief A simple example of sending an encrypted data to the Tangle.
 *
 */

#include <stdio.h>
#include <string.h>

#include "client/api/restful/get_message.h"
#include "client/api/restful/send_tagged_data.h"
#include "core/models/payloads/tagged_data.h"

#define XOR_KEY 'S'
#define TAG "iota.c\xF0\x9F\xA6\x8B"
#define DATA "Hello from encrypted data message example."

/**
 * @brief Simple encryption/decryption algorithm for this example
 *
 * @param src A string for encryption/decryption
 * @param dest A buffer which stores an encrypted/decrypted data
 * @param dest_len A buffer length
 * @return int 0 on success
 */
static int xor_encrypt_decrypt(byte_t *src, size_t src_len, byte_t *dest, size_t dest_len) {
  if (src_len > dest_len - 1) {
    // destination buffer too small
    return -1;
  }

  for (size_t i = 0; i < src_len; i++) {
    dest[i] = src[i] ^ XOR_KEY;
  }
  dest[src_len] = '\0';

  return 0;
}

int main(void) {
  iota_client_conf_t ctx = {.host = "localhost", .port = 443, .use_tls = true};

  byte_t encrypted[100] = {};
  byte_t decrypted[100] = {};

  // data encryption
  if (xor_encrypt_decrypt((byte_t *)DATA, strlen(DATA), encrypted, sizeof(encrypted)) != 0) {
    printf("Failed to encrypt data!\n");
    return -1;
  }

  // send encrypted data
  printf("Sending encrypted data message to the Tangle...\n");
  res_send_message_t res = {};
  if (send_tagged_data_message(&ctx, 2, (byte_t *)TAG, strlen(TAG), encrypted, strlen((char *)encrypted), &res) == 0) {
    if (res.is_error) {
      printf("API response: %s\n", res.u.error->msg);
      return -1;
    }
  } else {
    printf("Sending message failed!\n");
    return -1;
  }

  printf("Message successfully sent.\n");
  printf("Message ID: %s\nEncrypted data: %s\n", res.u.msg_id, encrypted);

  res_message_t *msg = res_message_new();
  if (!msg) {
    printf("Failed to create a response message object!\n");
    return -1;
  }

  // fetch message from the Tangle
  printf("Fetching message from the Tangle...\n");
  if (get_message_by_id(&ctx, res.u.msg_id, msg) == 0) {
    if (msg->is_error) {
      printf("API response: %s\n", msg->u.error->msg);
      res_message_free(msg);
      return -1;
    }
  } else {
    printf("Fetching message from a node failed!\n");
    res_message_free(msg);
    return -1;
  }

  printf("Message successfully fetched.\n");

  // check if fetched message is Tagged Data message
  if (msg->u.msg->payload_type != CORE_MESSAGE_PAYLOAD_TAGGED) {
    printf("Fetched message is not a Tagged Data message!\n");
    res_message_free(msg);
    return -1;
  }

  // get data from a retrieved message
  byte_t message_data[100] = {};
  uint8_t message_data_size = ((tagged_data_payload_t *)msg->u.msg->payload)->data->len;
  memcpy(message_data, ((tagged_data_payload_t *)msg->u.msg->payload)->data->data, message_data_size);

  // free response message object
  res_message_free(msg);

  // data decryption
  if (xor_encrypt_decrypt(message_data, message_data_size, decrypted, sizeof(decrypted)) != 0) {
    printf("Failed to decrypt data!\n");
    return -1;
  }
  printf("Decrypted data: %s\n", decrypted);

  // check if original data and decrypted data are matching
  if (memcmp(DATA, decrypted, strlen(DATA)) == 0) {
    printf("Original data and decrypted data match!\n");
  } else {
    printf("Original data and decrypted data do not match!\n");
  }

  return 0;
}
