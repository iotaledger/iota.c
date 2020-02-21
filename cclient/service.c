/*
 * Copyright (c) 2018 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

#include "cclient/service.h"
#include "cclient/serialization/json/json_serializer.h"

retcode_t iota_client_service_init(iota_client_service_t* const serv) {
  // init serializer
  if (serv->serializer_type == SR_JSON) {
    init_json_serializer(&serv->serializer);
  } else {
    return RC_CCLIENT_UNIMPLEMENTED;
  }
  return RC_OK;
}
