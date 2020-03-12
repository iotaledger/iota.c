/*
 * Copyright (c) 2019 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

#include "cclient/api/examples/cclient_examples.h"

static char const *amazon_ca1_pem =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\r\n"
    "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\r\n"
    "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\r\n"
    "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\r\n"
    "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\r\n"
    "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\r\n"
    "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\r\n"
    "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\r\n"
    "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\r\n"
    "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\r\n"
    "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\r\n"
    "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\r\n"
    "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\r\n"
    "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\r\n"
    "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\r\n"
    "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\r\n"
    "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\r\n"
    "rqXRfboQnoZsG4q5WTP468SQvvG5\r\n"
    "-----END CERTIFICATE-----\r\n";

// #define _USE_HTTP_

int main() {
  iota_client_service_t *serv = NULL;

#ifdef _USE_HTTP_
  serv = iota_client_core_init("altnodes.devnet.iota.org", 80, NULL);
#else  // HTTPS
#ifdef IOTA_CONFIG_MAINNET
  serv = iota_client_core_init("nodes.thetangle.org", 443, amazon_ca1_pem);
#else
  serv = iota_client_core_init("nodes.devnet.iota.org", 443, amazon_ca1_pem);
#endif
#endif

  if (serv == NULL) {
    printf("client init failed\n");
    exit(-1);
  }

  // init logger
  logger_helper_init(LOGGER_DEBUG);
  logger_init_client_core(LOGGER_DEBUG);
  logger_init_client_extended(LOGGER_DEBUG);
  logger_init_json_serializer(LOGGER_DEBUG);

#ifdef _USE_HTTP_
  printf("Connecting to node: http://%s:%u\n", serv->http.host, serv->http.port);
#else
  printf("Connecting to node: https://%s:%u\n", serv->http.host, serv->http.port);
#endif

  /* Core APIs */
  // example_attach_to_tangle(serv);
  // example_broadcast_transactions(serv);
  // example_check_consistency(serv);
  // example_find_transactions(serv);
  // example_get_balance(serv);
  // example_get_inclusion_states(serv);
  // example_get_transactions_to_approve(serv);
  // example_get_trytes(serv);
  // example_node_api_conf(serv);
  example_node_info(serv);
  // example_prepare_transfer(serv);
  // example_store_transactions(serv);
  // example_were_addresses_spent_from(serv);

  /* Extended APIs */
  // example_get_new_address(serv);
  // example_get_inputs(serv);
  // example_get_account_data(serv);
  // example_find_transaction_objects(serv);
  // example_is_promotable(serv);
  // example_get_latest_inclusion(serv);
  // example_send_trytes(serv);
  // example_traverse_bundle(serv);
  // example_get_bundle(serv);
  // example_replay_bundle(serv);
  // example_broadcast_bundle(serv);
  // example_promote_transaction(serv);
  // example_get_unspent_address(serv);

  /* Send data and balance */
  // example_send_data(serv);
  // example_send_balance(serv);

  // cleanup client service
  iota_client_core_destroy(&serv);
  // cleanup logger
  logger_destroy_client_core();
  logger_destroy_client_extended();
  logger_destroy_json_serializer();
  logger_helper_destroy();
  return 0;
}
