/*
 * Copyright (c) 2019 IOTA Stiftung
 * https://github.com/iotaledger/iota.c
 *
 * Refer to the LICENSE file for licensing information
 */

#include "cclient/api/tests/cclient_test_defs.h"

static iota_client_service_t *g_serv;

static void test_add_neighbors_empty(void) {
  g_serv = cclient_service_setup();
  TEST_ASSERT_NOT_NULL(g_serv);

  add_neighbors_req_t *nb_req = add_neighbors_req_new();
  TEST_ASSERT_NOT_NULL(nb_req);
  TEST_ASSERT_NOT_NULL(nb_req->uris);

  add_neighbors_res_t *nb_res = add_neighbors_res_new();
  TEST_ASSERT_NOT_NULL(nb_res);
  TEST_ASSERT_EQUAL_INT(0, nb_res->added_neighbors);

  TEST_ASSERT_EQUAL_INT16(RC_NULL_PARAM, iota_client_add_neighbors(g_serv, nb_req, nb_res));

  add_neighbors_req_free(&nb_req);
  TEST_ASSERT_NULL(nb_req);
  add_neighbors_res_free(&nb_res);
  TEST_ASSERT_NULL(nb_res);

  cclient_service_cleanup(&g_serv);
  TEST_ASSERT_NULL(g_serv);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_add_neighbors_empty);

  return UNITY_END();
}
