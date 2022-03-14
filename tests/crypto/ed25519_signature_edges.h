// Copyright 2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#ifndef _ED25519_SIGNATURE_EDGES_H__
#define _ED25519_SIGNATURE_EDGES_H__

#define ED25519_EDGE_SIG_COUNT (sizeof(ed25519_edge_sig) / sizeof(ed25519_edge_signature_t))

/**
 * @brief test vector struct
 *
 */
typedef struct {
  char *address;
  char *message;
  char *pub_key;
  char *signature;
} ed25519_edge_signature_t;

static ed25519_edge_signature_t ed25519_edge_sig[] = {
    {"008f5a6fdcfef8989fb88312cbc956ccc54dceb9c693ec99c08a28bdda5f11da44",
     "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000"
     "000000000000000000000000000000000000000000000000000"},
    {"008f5a6fdcfef8989fb88312cbc956ccc54dceb9c693ec99c08a28bdda5f11da44",
     "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be7"
     "9fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
    {"00df7de50e110ead8cb83451a503dbe03cc5edb2eced7e35212ae10af28d38c000",
     "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
     "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca"
     "5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"},
    {"001482f60b75cc1a6b1fe9810b64b95a978c35ed73ff371cb99f6f1fd0479d7b21",
     "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
     "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
     "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7"
     "a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"},
    {"001482f60b75cc1a6b1fe9810b64b95a978c35ed73ff371cb99f6f1fd0479d7b21",
     "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
     "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
     "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269"
     "b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"},
    {"001482f60b75cc1a6b1fe9810b64b95a978c35ed73ff371cb99f6f1fd0479d7b21",
     "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
     "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
     "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f"
     "71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"},
    {"002aeb2a345ceecd740ffa7cd891ac0116dd10fe169079d158e492043ec49b834d",
     "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
     "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
     "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2d"
     "dcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"},
    {"002aeb2a345ceecd740ffa7cd891ac0116dd10fe169079d158e492043ec49b834d",
     "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
     "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
     "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a47347"
     "4f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22"},
    {"00df7de50e110ead8cb83451a503dbe03cc5edb2eced7e35212ae10af28d38c000",
     "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102"
     "edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f"},
    {"00df7de50e110ead8cb83451a503dbe03cc5edb2eced7e35212ae10af28d38c000",
     "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
     "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208"
     "982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908"},
    {"00f25275baf4e267a1ec213dfd8283e9c97bf8c3494752c1c14b4bd5e5f9bfa9d8",
     "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be7"
     "9fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
    {"003e7cca5d2979e71caa7325ce147026402da2aec6f95586be89e24f84bfb7f8fc",
     "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be7"
     "9fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"}};

#if defined(CRYPTO_USE_SODIUM)
// Excpected signature validity for the above test vectors when tested with libsodium library
static bool edge_sig_libsodium_res[ED25519_EDGE_SIG_COUNT] = {false, false, false, true,  false, false,
                                                              false, false, false, false, false, false};

#elif defined(CRYPTO_USE_ED25519_DONNA)
// Excpected signature validity for the above test vectors when tested with ed25519_donna library
static bool edge_sig_ed25519_donna_res[ED25519_EDGE_SIG_COUNT] = {true, true,  true,  true,  false, false,
                                                                  true, false, false, false, false, true};
#endif

#endif
