#[[
// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
]]

if (NOT __ED25519_INCLUDE)
  set(__ED25519_INCLUDE TRUE)

  ExternalProject_Add(
    ed25519_download
    PREFIX ${PROJECT_BINARY_DIR}/ed25519
    DOWNLOAD_DIR ${PROJECT_BINARY_DIR}/download
    # DOWNLOAD_NAME 8757bd4cd209cb032853ece0ce413f122eef212c.tar.gz
    URL https://github.com/floodyberry/ed25519-donna/archive/8757bd4cd209cb032853ece0ce413f122eef212c.tar.gz
    URL_HASH SHA256=affbf8078b963f449fdafbc49a1e98389c6abf65fc6d49b051e7cbcf60764d1e
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_COMMAND ""
    # for debug
    # LOG_DOWNLOAD 1
  )

  set(ed25519_cmake_dir ${PROJECT_BINARY_DIR}/ed25519/src/ext_ed25519)
  set(ed25519_src_dir ../ed25519_download)
  set(ed25519_install_include ${CMAKE_INSTALL_PREFIX}/include/)
  set(ed25519_install_lib ${CMAKE_INSTALL_PREFIX}/lib)

  file(WRITE ${ed25519_cmake_dir}/CMakeLists.txt
    "cmake_minimum_required(VERSION 3.15)\n"
    "project(ed25519 C)\n"
    "option(CRYPTO_MBEDTLS \"Use mbedtls hash function\" OFF)\n"
    "option(CRYPTO_OPENSSL \"Use openssl hash function\" OFF)\n"
    "if(CRYPTO_OPENSSL)\n"
    "  find_package(OpenSSL REQUIRED)\n"
    "  message(\"OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}\")\n"
    "  message(\"OpenSSL libraries: ${OPENSSL_LIBRARIES}\")\n"
    "endif()\n"
    "add_library(ed25519_donna STATIC)\n"
    "target_sources(\n"
    "ed25519_donna\n"
    "PRIVATE \"${ed25519_src_dir}/curve25519-donna-32bit.h\"\n"
    "  \"${ed25519_src_dir}/curve25519-donna-64bit.h\"\n"
    "  \"${ed25519_src_dir}/curve25519-donna-helpers.h\"\n"
    "  \"${ed25519_src_dir}/curve25519-donna-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519.c\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-32bit-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-32bit-tables.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-tables.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-x86-32bit.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-64bit-x86.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-basepoint-table.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-batchverify.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-impl-base.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-impl-sse2.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-portable.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-donna-portable-identify.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-hash-custom.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-hash.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-randombytes-custom.h\"\n"
    "  \"${ed25519_src_dir}/ed25519-randombytes.h\"\n"
    "  \"${ed25519_src_dir}/modm-donna-32bit.h\"\n"
    "  \"${ed25519_src_dir}/modm-donna-64bit.h\"\n"
    "PUBLIC \"${ed25519_src_dir}/ed25519.h\")\n"
    "if(CRYPTO_OPENSSL)\n"
    "  target_link_libraries(ed25519_donna INTERFACE ${OPENSSL_LIBRARIES})\n"
    "  target_include_directories(ed25519_donna PUBLIC ${ed25519_src_dir} ${OPENSSL_INCLUDE_DIR})\n"
    "endif()\n"
    "if(CRYPTO_MBEDTLS)\n"
    "  target_compile_definitions(ed25519_donna PRIVATE ED25519_CUSTOMHASH)\n"
    "  target_compile_definitions(ed25519_donna PRIVATE ED25519_CUSTOMRANDOM)\n"
    "  target_link_libraries(ed25519_donna INTERFACE mbedcrypto mbedtls mbedx509)\n"
    "  target_include_directories(ed25519_donna PUBLIC ${ed25519_src_dir} ${CMAKE_INSTALL_PREFIX}/include)\n"
    "  file(WRITE ${ed25519_src_dir}/ed25519-hash-custom.h"
    "    \"#include <stdlib.h>\n\""
    "    \"#include \\\"mbedtls/sha512.h\\\"\n\""
    "    \"typedef mbedtls_sha512_context ed25519_hash_context;\n\""
    "    \"void ed25519_hash_init(ed25519_hash_context *ctx){mbedtls_sha512_init(ctx); mbedtls_sha512_starts(ctx, 0);}\n\""
    "    \"void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen){mbedtls_sha512_update(ctx, in, inlen);}\n\""
    "    \"void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash){mbedtls_sha512_finish(ctx, hash); mbedtls_sha512_free(ctx);}\n\""
    "    \"void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen){mbedtls_sha512(in, inlen, hash, 0);}\n\""
    "  )\n"
    "  file(WRITE ${ed25519_src_dir}/ed25519-randombytes-custom.h"
    "    \"#include <stdlib.h>\n\""
    "    \"#include \\\"mbedtls/ctr_drbg.h\\\"\n\""
    "    \"#include \\\"mbedtls/entropy.h\\\"\n\""
    "    \"void ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len){\n\""
    "    \"  int ret = 0; mbedtls_ctr_drbg_context drbg; mbedtls_entropy_context ent;\n\""
    "    \"  mbedtls_ctr_drbg_init(&drbg);\n\""
    "    \"  mbedtls_entropy_init(&ent);\n\""
    "    \"  ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (unsigned char const *)\\\"CTR_DRBG\\\", 8);\n\""
    "    \"  if (ret == 0) { mbedtls_ctr_drbg_random(&drbg, p, len); }\n\""
    "    \"  mbedtls_entropy_free(&ent);\n\""
    "    \"  mbedtls_ctr_drbg_free(&drbg);\n\""
    "    \"}\n\""
    "  )\n"
    "endif()\n"
    "install(TARGETS ed25519_donna DESTINATION ${ed25519_install_lib})\n"
    "install(FILES ${ed25519_src_dir}/ed25519.h DESTINATION ${ed25519_install_include})\n"
  )

  if(__MBEDTLS_INCLUDED)
    ExternalProject_Add(
      ext_ed25519
      PREFIX ${PROJECT_BINARY_DIR}/ed25519
      DOWNLOAD_COMMAND ""
      BUILD_IN_SOURCE TRUE
      CMAKE_ARGS
        -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}
        -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
        -DCRYPTO_MBEDTLS:BOOL=TRUE
      # for debug
      # LOG_CONFIGURE 1
      # LOG_INSTALL 1
    )
    add_dependencies(ext_ed25519 ed25519_download ext_mbedtls)

  else()
    find_package(OpenSSL REQUIRED)
    ExternalProject_Add(
      ext_ed25519
      PREFIX ${PROJECT_BINARY_DIR}/ed25519
      DOWNLOAD_COMMAND ""
      BUILD_IN_SOURCE TRUE
      CMAKE_ARGS
        -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX:STRING=${CMAKE_INSTALL_PREFIX}
        -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
        -DCRYPTO_OPENSSL:BOOL=TRUE
      # for debug
      # LOG_CONFIGURE 1
      # LOG_INSTALL 1
    )
    add_dependencies(ext_ed25519 ed25519_download)

  endif()

endif()
