// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>

#include "core/address.h"
#include "core/constants.h"
#include "core/utils/byte_buffer.h"
#include "core/utils/macros.h"
#include "crypto/iota_crypto.h"
#include "unity/unity.h"

void setUp(void) {}

void tearDown(void) {}

void test_ed25519_gen_from_seed_iota_network() {
  byte_t exp_addr[] = {0x00, 0x51, 0x55, 0x82, 0xfe, 0x64, 0x8b, 0xf,  0x10, 0xa2, 0xb2,
                       0xa1, 0xb9, 0x1d, 0x75, 0x2,  0x19, 0xc,  0x97, 0x9b, 0xaa, 0xbf,
                       0xee, 0x85, 0xb6, 0xbb, 0xb5, 0x2,  0x6,  0x92, 0xe5, 0x5d, 0x16};
  address_t ed25519_addr = {};
  byte_t seed[32] = {};
  byte_t ed25519_serialized[33] = {};
  char bech32_str[65] = {};
  // convert seed from hex string to binary
  TEST_ASSERT(hex_2_bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", 64, NULL, seed, 32) == 0);
  // dump_hex(seed, 32);

  TEST_ASSERT(ed25519_address_from_path(seed, sizeof(seed), "m/44'/4218'/0'/0'/0'", &ed25519_addr) == 0);
  // dump_hex(ed25519_addr.address, 32);
  size_t ser_len = address_serialize(&ed25519_addr, ed25519_serialized, sizeof(ed25519_serialized));
  TEST_ASSERT(ser_len == address_serialized_len(&ed25519_addr));
  // dump_hex(ed25519_serialized, ser_len);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, ed25519_serialized, ser_len);

  // convert binary address to bech32 with iota HRP
  char const* const exp_iota_bech32 = "iota1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v79tf3l";
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_iota_bech32, bech32_str);
  // printf("bech32 [iota]: %s\n", bech32_str);

  // bech32 to address object
  address_t from_bech32 = {};
  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_ed25519_gen_from_seed_iota_test_network() {
  byte_t exp_addr[] = {0x00, 0x51, 0x55, 0x82, 0xfe, 0x64, 0x8b, 0xf,  0x10, 0xa2, 0xb2,
                       0xa1, 0xb9, 0x1d, 0x75, 0x2,  0x19, 0xc,  0x97, 0x9b, 0xaa, 0xbf,
                       0xee, 0x85, 0xb6, 0xbb, 0xb5, 0x2,  0x6,  0x92, 0xe5, 0x5d, 0x16};
  address_t ed25519_addr = {};
  byte_t seed[32] = {};
  byte_t ed25519_serialized[33] = {};
  char bech32_str[65] = {};
  // convert seed from hex string to binary
  TEST_ASSERT(hex_2_bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", 64, NULL, seed, 32) == 0);
  // dump_hex(seed, 32);

  TEST_ASSERT(ed25519_address_from_path(seed, sizeof(seed), "m/44'/4218'/0'/0'/0'", &ed25519_addr) == 0);
  // dump_hex(ed25519_addr.address, 32);
  size_t ser_len = address_serialize(&ed25519_addr, ed25519_serialized, sizeof(ed25519_serialized));
  TEST_ASSERT(ser_len == address_serialized_len(&ed25519_addr));
  // dump_hex(ed25519_serialized, ser_len);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, ed25519_serialized, ser_len);

  // convert binary address to bech32 with atoi HRP
  char const* const exp_atoi_bech32 = "atoi1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3vet6gtj";
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "atoi", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_atoi_bech32, bech32_str);
  // printf("bech32 [atoi]: %s\n", bech32_str);

  // bech32 to address object
  address_t from_bech32 = {};
  TEST_ASSERT(address_from_bech32("atoi", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_ed25519_gen_from_seed_shimmer_network() {
  byte_t exp_addr[] = {0x0,  0xb5, 0x77, 0x99, 0xbf, 0x74, 0xe,  0x89, 0x46, 0xfe, 0x4a,
                       0x31, 0xf4, 0xcf, 0x37, 0x66, 0x38, 0x4a, 0xd4, 0xe2, 0x47, 0x22,
                       0xb1, 0x54, 0xc,  0x62, 0x3a, 0x44, 0x84, 0x6d, 0xe,  0x75, 0xa0};
  address_t ed25519_addr = {};
  byte_t seed[32] = {};
  byte_t ed25519_serialized[33] = {};
  char bech32_str[65] = {};
  // convert seed from hex string to binary
  TEST_ASSERT(hex_2_bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", 64, NULL, seed, 32) == 0);
  // dump_hex(seed, 32);

  TEST_ASSERT(ed25519_address_from_path(seed, sizeof(seed), "m/44'/4219'/0'/0'/0'", &ed25519_addr) == 0);
  // dump_hex(ed25519_addr.address, 32);
  size_t ser_len = address_serialize(&ed25519_addr, ed25519_serialized, sizeof(ed25519_serialized));
  TEST_ASSERT(ser_len == address_serialized_len(&ed25519_addr));
  // dump_hex(ed25519_serialized, ser_len);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, ed25519_serialized, ser_len);

  // convert binary address to bech32 with smr HRP
  char const* const exp_smr_bech32 = "smr1qz6h0xdlws8gj3h7fgclfnehvcuy448zgu3tz4qvvgayfprdpe66qpkmarp";
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "smr", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_smr_bech32, bech32_str);
  // printf("bech32 [smr]: %s\n", bech32_str);

  // bech32 to address object
  address_t from_bech32 = {};
  TEST_ASSERT(address_from_bech32("smr", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_ed25519_gen_from_seed_shimmer_test_network() {
  byte_t exp_addr[] = {0x0,  0xb5, 0x77, 0x99, 0xbf, 0x74, 0xe,  0x89, 0x46, 0xfe, 0x4a,
                       0x31, 0xf4, 0xcf, 0x37, 0x66, 0x38, 0x4a, 0xd4, 0xe2, 0x47, 0x22,
                       0xb1, 0x54, 0xc,  0x62, 0x3a, 0x44, 0x84, 0x6d, 0xe,  0x75, 0xa0};
  address_t ed25519_addr = {};
  byte_t seed[32] = {};
  byte_t ed25519_serialized[33] = {};
  char bech32_str[65] = {};
  // convert seed from hex string to binary
  TEST_ASSERT(hex_2_bin("e57fb750f3a3a67969ece5bd9ae7eef5b2256a818b2aac458941f7274985a410", 64, NULL, seed, 32) == 0);
  // dump_hex(seed, 32);

  TEST_ASSERT(ed25519_address_from_path(seed, sizeof(seed), "m/44'/4219'/0'/0'/0'", &ed25519_addr) == 0);
  // dump_hex(ed25519_addr.address, 32);
  size_t ser_len = address_serialize(&ed25519_addr, ed25519_serialized, sizeof(ed25519_serialized));
  TEST_ASSERT(ser_len == address_serialized_len(&ed25519_addr));
  // dump_hex(ed25519_serialized, ser_len);
  TEST_ASSERT_EQUAL_MEMORY(exp_addr, ed25519_serialized, ser_len);

  // convert binary address to bech32 with rms HRP
  char const* const exp_rms_bech32 = "rms1qz6h0xdlws8gj3h7fgclfnehvcuy448zgu3tz4qvvgayfprdpe66q43s8cc";
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "rms", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT_EQUAL_STRING(exp_rms_bech32, bech32_str);
  // printf("bech32 [rms]: %s\n", bech32_str);

  // bech32 to address object
  address_t from_bech32 = {};
  TEST_ASSERT(address_from_bech32("rms", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_ed25519_gen_iota_network() {
  // ed25519 address
  address_t ed25519_addr = {};
  ed25519_addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_addr.address, ED25519_PUBKEY_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("iota1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xqgyzyx", bech32_str) == 0);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);

  // create ed25519 address from public key
  byte_t ed25519_public_key[ED25519_PUBKEY_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("6f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_public_key, ED25519_PUBKEY_BYTES) == 0);
  TEST_ASSERT(address_from_ed25519_pub(ed25519_public_key, &ed25519_addr) == 0);

  TEST_ASSERT(address_to_bech32(&ed25519_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("iota1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xqgyzyx", bech32_str) == 0);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_ed25519_gen_iota_test_network() {
  // ed25519 address
  address_t ed25519_addr = {};
  ed25519_addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_addr.address, ED25519_PUBKEY_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "atoi", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("atoi1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6x8x4r7t", bech32_str) == 0);
  // printf("bech32 [atoi]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("atoi", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);

  // create ed25519 address from public key
  byte_t ed25519_public_key[ED25519_PUBKEY_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("6f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_public_key, ED25519_PUBKEY_BYTES) == 0);
  TEST_ASSERT(address_from_ed25519_pub(ed25519_public_key, &ed25519_addr) == 0);

  TEST_ASSERT(address_to_bech32(&ed25519_addr, "atoi", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("atoi1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6x8x4r7t", bech32_str) == 0);
  // printf("bech32 [atoi]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("atoi", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_ed25519_gen_shimmer_network() {
  // ed25519 address
  address_t ed25519_addr = {};
  ed25519_addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_addr.address, ED25519_PUBKEY_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "smr", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("smr1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xhcazjh", bech32_str) == 0);
  // printf("bech32 [smr]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("smr", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);

  // create ed25519 address from public key
  byte_t ed25519_public_key[ED25519_PUBKEY_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("6f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_public_key, ED25519_PUBKEY_BYTES) == 0);
  TEST_ASSERT(address_from_ed25519_pub(ed25519_public_key, &ed25519_addr) == 0);

  TEST_ASSERT(address_to_bech32(&ed25519_addr, "smr", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("smr1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xhcazjh", bech32_str) == 0);
  // printf("bech32 [smr]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("smr", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_ed25519_gen_shimmer_test_network() {
  // ed25519 address
  address_t ed25519_addr = {};
  ed25519_addr.type = ADDRESS_TYPE_ED25519;
  TEST_ASSERT(hex_2_bin("efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_addr.address, ED25519_PUBKEY_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&ed25519_addr, "rms", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("rms1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xrlkcfw", bech32_str) == 0);
  // printf("bech32 [rms]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("rms", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);

  // create ed25519 address from public key
  byte_t ed25519_public_key[ED25519_PUBKEY_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("6f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8",
                        BIN_TO_HEX_BYTES(ED25519_PUBKEY_BYTES), NULL, ed25519_public_key, ED25519_PUBKEY_BYTES) == 0);
  TEST_ASSERT(address_from_ed25519_pub(ed25519_public_key, &ed25519_addr) == 0);

  TEST_ASSERT(address_to_bech32(&ed25519_addr, "rms", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("rms1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xrlkcfw", bech32_str) == 0);
  // printf("bech32 [rms]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("rms", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&ed25519_addr, &from_bech32) == true);
}

void test_alias_gen_iota_network() {
  // alias address
  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  TEST_ASSERT(hex_2_bin("01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248",
                        BIN_TO_HEX_BYTES(ALIAS_ID_BYTES), NULL, alias_addr.address, ALIAS_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&alias_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("iota1pqq64rfq9fgm2a0tjfyt94vqm3s5j5y07z20crkhnsj5s6f4t9eysrgtqzj", bech32_str) == 0);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);

  // create alias address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c6490000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(alias_address_from_output(output_id, sizeof(output_id), &alias_addr) == 0);

  TEST_ASSERT(address_to_bech32(&alias_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("iota1prlgpsht03ekmghhex8v7y67a835uns8dtlxu807hj0v279c74kj76j6rev", bech32_str) == 0);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);
}

void test_alias_gen_iota_test_network() {
  // alias address
  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  TEST_ASSERT(hex_2_bin("01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248",
                        BIN_TO_HEX_BYTES(ALIAS_ID_BYTES), NULL, alias_addr.address, ALIAS_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&alias_addr, "atoi", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("atoi1pqq64rfq9fgm2a0tjfyt94vqm3s5j5y07z20crkhnsj5s6f4t9eysyx6pcl", bech32_str) == 0);
  // printf("bech32 [atoi]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("atoi", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);

  // create alias address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c6490000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(alias_address_from_output(output_id, sizeof(output_id), &alias_addr) == 0);

  TEST_ASSERT(address_to_bech32(&alias_addr, "atoi", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("atoi1prlgpsht03ekmghhex8v7y67a835uns8dtlxu807hj0v279c74kj7autzrp", bech32_str) == 0);
  // printf("bech32 [atoi]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("atoi", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);
}

void test_alias_gen_shimmer_network() {
  // alias address
  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  TEST_ASSERT(hex_2_bin("01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248",
                        BIN_TO_HEX_BYTES(ALIAS_ID_BYTES), NULL, alias_addr.address, ALIAS_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&alias_addr, "smr", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("smr1pqq64rfq9fgm2a0tjfyt94vqm3s5j5y07z20crkhnsj5s6f4t9eys5cjq5r", bech32_str) == 0);
  // printf("bech32 [smr]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("smr", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);

  // create alias address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c6490000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(alias_address_from_output(output_id, sizeof(output_id), &alias_addr) == 0);

  TEST_ASSERT(address_to_bech32(&alias_addr, "smr", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("smr1prlgpsht03ekmghhex8v7y67a835uns8dtlxu807hj0v279c74kj7dzrr0a", bech32_str) == 0);
  // printf("bech32 [smr]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("smr", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);
}

void test_alias_gen_shimmer_test_network() {
  // alias address
  address_t alias_addr = {};
  alias_addr.type = ADDRESS_TYPE_ALIAS;
  TEST_ASSERT(hex_2_bin("01aa8d202a51b575eb9248b2d580dc6149508ff094fc0ed79c25486935597248",
                        BIN_TO_HEX_BYTES(ALIAS_ID_BYTES), NULL, alias_addr.address, ALIAS_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&alias_addr, "rms", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("rms1pqq64rfq9fgm2a0tjfyt94vqm3s5j5y07z20crkhnsj5s6f4t9eysqle606", bech32_str) == 0);
  // printf("bech32 [rms]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("rms", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);

  // create alias address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c6490000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(alias_address_from_output(output_id, sizeof(output_id), &alias_addr) == 0);

  TEST_ASSERT(address_to_bech32(&alias_addr, "rms", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("rms1prlgpsht03ekmghhex8v7y67a835uns8dtlxu807hj0v279c74kj7e9ge5y", bech32_str) == 0);
  // printf("bech32 [rms]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("rms", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&alias_addr, &from_bech32) == true);
}

void test_nft_gen_iota_network() {
  // NFT address
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  TEST_ASSERT(hex_2_bin("19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f",
                        BIN_TO_HEX_BYTES(NFT_ID_BYTES), NULL, nft_addr.address, NFT_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&nft_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("iota1zqvus2ejwc0asu56rfk80a7pwkt7fwdszavhjnjj8q0k5qzskrq379njp5j", bech32_str) == 0);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);

  // create NFT address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("97b9d84d33419199483daab1f81ddccdeff478b6ee9040cfe026c517f67757880000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(nft_address_from_output(output_id, sizeof(output_id), &nft_addr) == 0);

  TEST_ASSERT(address_to_bech32(&nft_addr, "iota", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("iota1zqc4nvg4ufcj3dkmzmd4uc034fx8pkz2nxl820a28mnsmxkec6ntw0vklm7", bech32_str) == 0);
  // printf("bech32 [iota]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("iota", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);
}

void test_nft_gen_iota_test_network() {
  // NFT address
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  TEST_ASSERT(hex_2_bin("19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f",
                        BIN_TO_HEX_BYTES(NFT_ID_BYTES), NULL, nft_addr.address, NFT_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&nft_addr, "atoi", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("atoi1zqvus2ejwc0asu56rfk80a7pwkt7fwdszavhjnjj8q0k5qzskrq37zarqwl", bech32_str) == 0);
  // printf("bech32 [atoi]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("atoi", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);

  // create NFT address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("97b9d84d33419199483daab1f81ddccdeff478b6ee9040cfe026c517f67757880000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(nft_address_from_output(output_id, sizeof(output_id), &nft_addr) == 0);

  TEST_ASSERT(address_to_bech32(&nft_addr, "atoi", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("atoi1zqc4nvg4ufcj3dkmzmd4uc034fx8pkz2nxl820a28mnsmxkec6ntwgz87pn", bech32_str) == 0);
  // printf("bech32 [atoi]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("atoi", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);
}

void test_nft_gen_shimmer_network() {
  // NFT address
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  TEST_ASSERT(hex_2_bin("19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f",
                        BIN_TO_HEX_BYTES(NFT_ID_BYTES), NULL, nft_addr.address, NFT_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&nft_addr, "smr", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("smr1zqvus2ejwc0asu56rfk80a7pwkt7fwdszavhjnjj8q0k5qzskrq37jrtpzr", bech32_str) == 0);
  // printf("bech32 [smr]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("smr", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);

  // create NFT address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("97b9d84d33419199483daab1f81ddccdeff478b6ee9040cfe026c517f67757880000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(nft_address_from_output(output_id, sizeof(output_id), &nft_addr) == 0);

  TEST_ASSERT(address_to_bech32(&nft_addr, "smr", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("smr1zqc4nvg4ufcj3dkmzmd4uc034fx8pkz2nxl820a28mnsmxkec6ntwcu0ld0", bech32_str) == 0);
  // printf("bech32 [smr]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("smr", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);
}

void test_nft_gen_shimmer_test_network() {
  // NFT address
  address_t nft_addr = {};
  nft_addr.type = ADDRESS_TYPE_NFT;
  TEST_ASSERT(hex_2_bin("19c82b32761fd8729a1a6c77f7c17597e4b9b01759794e52381f6a0050b0c11f",
                        BIN_TO_HEX_BYTES(NFT_ID_BYTES), NULL, nft_addr.address, NFT_ID_BYTES) == 0);

  address_t from_bech32 = {};
  char bech32_str[65] = {};
  TEST_ASSERT(address_to_bech32(&nft_addr, "rms", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("rms1zqvus2ejwc0asu56rfk80a7pwkt7fwdszavhjnjj8q0k5qzskrq37xyqme6", bech32_str) == 0);
  // printf("bech32 [rms]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("rms", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);

  // create NFT address from output ID
  byte_t output_id[IOTA_OUTPUT_ID_BYTES] = {0};
  TEST_ASSERT(hex_2_bin("97b9d84d33419199483daab1f81ddccdeff478b6ee9040cfe026c517f67757880000",
                        BIN_TO_HEX_BYTES(IOTA_OUTPUT_ID_BYTES), NULL, output_id, IOTA_OUTPUT_ID_BYTES) == 0);
  TEST_ASSERT(nft_address_from_output(output_id, sizeof(output_id), &nft_addr) == 0);

  TEST_ASSERT(address_to_bech32(&nft_addr, "rms", bech32_str, sizeof(bech32_str)) == 0);
  TEST_ASSERT(strcmp("rms1zqc4nvg4ufcj3dkmzmd4uc034fx8pkz2nxl820a28mnsmxkec6ntwvmy9kk", bech32_str) == 0);
  // printf("bech32 [rms]: %s\n", bech32_str);

  TEST_ASSERT(address_from_bech32("rms", bech32_str, &from_bech32) == 0);
  TEST_ASSERT(address_equal(&nft_addr, &from_bech32) == true);
}

void test_serializer() {
  byte_t addr_bin[ADDRESS_SERIALIZED_MAX_BYTES] = {};  // random data
  byte_t addr_ser[ADDRESS_SERIALIZED_MAX_BYTES] = {};  // serialized address
  address_t* addr_obj = NULL;                          // deserialized address
  size_t ser_len = 0;                                  // bytes written to serialized buffer

  // random address
  iota_crypto_randombytes(addr_bin, ADDRESS_SERIALIZED_MAX_BYTES);

  // ed25519 serializer
  addr_bin[0] = ADDRESS_TYPE_ED25519;
  // deserialize with insufficient buffer size
  TEST_ASSERT_NULL(address_deserialize(addr_bin, 1));
  // convert a binary to an address object
  addr_obj = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr_obj);
  TEST_ASSERT(addr_obj->type == ADDRESS_TYPE_ED25519);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj->address, ED25519_PUBKEY_BYTES);
  // serialize with insufficient buffer size
  TEST_ASSERT(address_serialize(addr_obj, addr_ser, 1) == 0);
  // convert an address object to a binary data
  ser_len = address_serialize(addr_obj, addr_ser, sizeof(addr_ser));
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, ser_len);
  address_free(addr_obj);

  // alias serializer
  addr_bin[0] = ADDRESS_TYPE_ALIAS;
  // convert a binary to an address object
  addr_obj = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr_obj);
  TEST_ASSERT(addr_obj->type == ADDRESS_TYPE_ALIAS);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj->address, ALIAS_ID_BYTES);
  // convert an address object to a binary data
  ser_len = address_serialize(addr_obj, addr_ser, sizeof(addr_ser));
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, ser_len);
  address_free(addr_obj);

  // nft serializer
  addr_bin[0] = ADDRESS_TYPE_NFT;
  // convert a binary to an address object
  addr_obj = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr_obj);
  TEST_ASSERT(addr_obj->type == ADDRESS_TYPE_NFT);
  TEST_ASSERT_EQUAL_MEMORY(addr_bin + 1, addr_obj->address, NFT_ID_BYTES);
  // convert an address object to a binary data
  ser_len = address_serialize(addr_obj, addr_ser, sizeof(addr_ser));
  TEST_ASSERT_EQUAL_MEMORY(addr_ser, addr_bin, ser_len);
  address_free(addr_obj);
}

void test_clone_equal() {
  byte_t addr_bin[ADDRESS_SERIALIZED_MAX_BYTES] = {};  // random data
  iota_crypto_randombytes(addr_bin, ADDRESS_SERIALIZED_MAX_BYTES);
  addr_bin[0] = ADDRESS_TYPE_ED25519;

  address_t* addr1 = address_deserialize(addr_bin, sizeof(addr_bin));
  TEST_ASSERT_NOT_NULL(addr1);
  address_t* addr2 = address_clone(addr1);
  TEST_ASSERT_NOT_NULL(addr2);
  TEST_ASSERT(address_equal(addr1, addr2) == true);

  iota_crypto_randombytes(addr2->address, ED25519_PUBKEY_BYTES);
  TEST_ASSERT(address_equal(addr1, addr2) == false);

  address_free(addr1);
  address_free(addr2);
}

int main() {
  UNITY_BEGIN();

  RUN_TEST(test_ed25519_gen_from_seed_iota_network);
  RUN_TEST(test_ed25519_gen_from_seed_iota_test_network);
  RUN_TEST(test_ed25519_gen_from_seed_shimmer_network);
  RUN_TEST(test_ed25519_gen_from_seed_shimmer_test_network);
  RUN_TEST(test_ed25519_gen_iota_network);
  RUN_TEST(test_ed25519_gen_iota_test_network);
  RUN_TEST(test_ed25519_gen_shimmer_network);
  RUN_TEST(test_ed25519_gen_shimmer_test_network);
  RUN_TEST(test_alias_gen_iota_network);
  RUN_TEST(test_alias_gen_iota_test_network);
  RUN_TEST(test_alias_gen_shimmer_network);
  RUN_TEST(test_alias_gen_shimmer_test_network);
  RUN_TEST(test_nft_gen_iota_network);
  RUN_TEST(test_nft_gen_iota_test_network);
  RUN_TEST(test_nft_gen_shimmer_network);
  RUN_TEST(test_nft_gen_shimmer_test_network);
  RUN_TEST(test_serializer);
  RUN_TEST(test_clone_equal);

  return UNITY_END();
}
