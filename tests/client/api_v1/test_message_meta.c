// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <stdio.h>
#include <unity/unity.h>

#include "client/api/v1/get_message_metadata.h"
#include "test_config.h"

void setUp(void) {}

void tearDown(void) {}

void test_deser_mileston_message() {
  char const* const json_mileston =
      "{\"data\":{\"messageId\":\"ebe0c79284d318a1bc36f1d2b6a94ea2ada27a1334d40c565823040131aa1ab4\","
      "\"parentMessageIds\":[\"214c29ffff6dc41da6898b8fc0cce3f9409a83b96ecbef513a7f4821dc0bc439\","
      "\"33cdc418bab0ad8d8c0052dccdb803674f0c3d28054ab74ebf8d549407ee7c5f\","
      "\"3ccaa501629fd70603f03a21b390bcb92de943610a5e551a0b81964d96139e99\","
      "\"405d31b131949d273a05e0018399b623d0e212030f758bdc632d3d38dcf8a8cc\","
      "\"c62ced72c07ca9ec0ba62ef6d0bdd16887411b5d3127d455e36a0b0a5facd7f0\"],\"isSolid\":true,"
      "\"referencedByMilestoneIndex\":285132,\"milestoneIndex\":285132,\"ledgerInclusionState\":\"noTransaction\"}}";

  res_msg_meta_t* meta = res_msg_meta_new();
  TEST_ASSERT_NOT_NULL(meta);

  int ret = deser_msg_meta(json_mileston, meta);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(meta->is_error);
  TEST_ASSERT_EQUAL_STRING("ebe0c79284d318a1bc36f1d2b6a94ea2ada27a1334d40c565823040131aa1ab4", meta->u.meta->msg_id);
  TEST_ASSERT_EQUAL_INT(5, res_msg_meta_parents_len(meta));
  TEST_ASSERT_EQUAL_STRING("214c29ffff6dc41da6898b8fc0cce3f9409a83b96ecbef513a7f4821dc0bc439",
                           res_msg_meta_parent_get(meta, 0));
  TEST_ASSERT_EQUAL_STRING("c62ced72c07ca9ec0ba62ef6d0bdd16887411b5d3127d455e36a0b0a5facd7f0",
                           res_msg_meta_parent_get(meta, 4));
  TEST_ASSERT_TRUE(meta->u.meta->is_solid);
  TEST_ASSERT(meta->u.meta->referenced_milestone == 285132);
  TEST_ASSERT(meta->u.meta->milestone_idx == 285132);
  TEST_ASSERT_EQUAL_STRING("noTransaction", meta->u.meta->inclusion_state);
  TEST_ASSERT(meta->u.meta->should_promote == -1);
  TEST_ASSERT(meta->u.meta->should_reattach == -1);
  res_msg_meta_free(meta);
}

void test_deser_tx_message() {
  char const* const json_mileston =
      "{\"data\":{\"messageId\":\"021a1d70ea18bddd171b70cb8ce9f7f02f712bc4e3c8bff6c2155d57111ae660\","
      "\"parentMessageIds\":[\"0dc75a753e1d139e92aaf66e42475c144bc21a102cf6ff2e685186266354f61b\","
      "\"666cfccdfcaa28539cc004a70f412b9a62a969f7a7082a84520f450a0d31b121\","
      "\"7e45e31042af8b80fcaa8536ef62aab751c9daa1278e0df42bc990ddd185e713\","
      "\"ee6a7fae8287c718c22d6304ebc8ee6f5cc5622be1d177f7c7733a9e7e8cf408\"],\"isSolid\":false,"
      "\"referencedByMilestoneIndex\":161055,\"ledgerInclusionState\":\"included\"}}";

  res_msg_meta_t* meta = res_msg_meta_new();
  TEST_ASSERT_NOT_NULL(meta);

  int ret = deser_msg_meta(json_mileston, meta);
  TEST_ASSERT_EQUAL_INT(0, ret);
  TEST_ASSERT_FALSE(meta->is_error);
  TEST_ASSERT_EQUAL_STRING("021a1d70ea18bddd171b70cb8ce9f7f02f712bc4e3c8bff6c2155d57111ae660", meta->u.meta->msg_id);
  TEST_ASSERT_EQUAL_INT(4, res_msg_meta_parents_len(meta));
  TEST_ASSERT_EQUAL_STRING("0dc75a753e1d139e92aaf66e42475c144bc21a102cf6ff2e685186266354f61b",
                           res_msg_meta_parent_get(meta, 0));
  TEST_ASSERT_EQUAL_STRING("ee6a7fae8287c718c22d6304ebc8ee6f5cc5622be1d177f7c7733a9e7e8cf408",
                           res_msg_meta_parent_get(meta, 3));
  TEST_ASSERT_NULL(res_msg_meta_parent_get(meta, 4));

  TEST_ASSERT_FALSE(meta->u.meta->is_solid);
  TEST_ASSERT(meta->u.meta->referenced_milestone == 161055);
  TEST_ASSERT(meta->u.meta->milestone_idx == 0);
  TEST_ASSERT_EQUAL_STRING("included", meta->u.meta->inclusion_state);
  TEST_ASSERT(meta->u.meta->should_promote == -1);
  TEST_ASSERT(meta->u.meta->should_reattach == -1);
  res_msg_meta_free(meta);
}

void test_get_msg_meta() {
  // Indexation payload
  // char const * const id_str = "ceeb2ea39da657abf0894c3e8abff66d30e243fec9446d8e409f99fa5be17c3c";
  // Mileston payload
  // char const * const id_str = "7424fb7b891db6d1703873cef7bcf6013c4b355f6477fe3de1b72ab19ba91a2c";
  // Transaction payload
  char const* const id_str = "460df94c91bdb2590df7e01ff5c8c30eb791b225545ff19b3cf86089bddc139e";

  iota_client_conf_t ctx = {.host = TEST_NODE_HOST, .port = TEST_NODE_PORT, .use_tls = TEST_IS_HTTPS};
  res_msg_meta_t* meta = res_msg_meta_new();
  TEST_ASSERT_NOT_NULL(meta);

  TEST_ASSERT(get_message_metadata(&ctx, id_str, meta) == 0);
  if (meta->is_error) {
    TEST_ASSERT_NOT_NULL(meta->u.error);
    printf("Error response: %s\n", meta->u.error->msg);
  } else {
    TEST_ASSERT_NOT_NULL(meta->u.meta);
    printf("Message ID: %s\nisSolid: %s\n", meta->u.meta->msg_id, meta->u.meta->is_solid ? "True" : "False");
    size_t parents = res_msg_meta_parents_len(meta);
    printf("%zu parents:\n", parents);
    for (size_t i = 0; i < parents; i++) {
      printf("\t%s\n", res_msg_meta_parent_get(meta, i));
    }
    printf("ledgerInclusionState: %s\n", meta->u.meta->inclusion_state);

    // check milestone index
    if (meta->u.meta->milestone_idx != 0) {
      printf("milestoneIndex: %" PRIu64 "\n", meta->u.meta->milestone_idx);
    }

    // check referenced milestone index
    if (meta->u.meta->referenced_milestone != 0) {
      printf("referencedByMilestoneIndex: %" PRIu64 "\n", meta->u.meta->referenced_milestone);
    }

    // check should promote
    if (meta->u.meta->should_promote >= 0) {
      printf("shouldPromote: %s\n", meta->u.meta->should_promote ? "True" : "False");
    }
    // check should reattach
    if (meta->u.meta->should_reattach >= 0) {
      printf("shouldReattach: %s\n", meta->u.meta->should_reattach ? "True" : "False");
    }
  }
  res_msg_meta_free(meta);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_deser_mileston_message);
  RUN_TEST(test_deser_tx_message);
#if TEST_TANGLE_ENABLE
  RUN_TEST(test_get_msg_meta);
#endif

  return UNITY_END();
}