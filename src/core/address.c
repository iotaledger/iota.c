#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libbase58.h"

#include "core/address.h"

void dump_hex(byte_t const data[], size_t len) {
  for (int i = 0; i < len; i++) {
    printf("0x%x, ", data[i]);
  }
  printf("\n");
}

/**
 * @brief hexadecimal text to a string, ex: "48656c6c6f" -> "Hello"
 *
 * @param str the hex text,
 * @param array output string
 */
void hex_decode_string(char const str[], uint8_t array[]) {
  size_t len = strlen(str) / 2;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') {
      c += (str[i * 2] - '0') << 4;
    }
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F') {
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    }
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
      c += (str[i * 2 + 1] - '0');
    }
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') {
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    }
    array[i] = c;
  }
}

void random_seed(byte_t seed[]) { randombytes_buf((void *const)seed, IOTA_SEED_BYTES); }

bool seed_2_base58(byte_t const seed[], char str_buf[], size_t *buf_len) {
  return b58enc((char *)str_buf, buf_len, (const void *)seed, IOTA_SEED_BYTES);
}

bool seed_from_base58(char const str[], byte_t out_seed[]) {
  size_t out_len = IOTA_SEED_BYTES;
  return b58tobin((void *)out_seed, &out_len, str, strlen(str));
}

// subSeed generates the n'th sub seed of this Seed which is then used to generate the KeyPair.
static void get_subseed(byte_t const seed[], uint64_t index, byte_t subseed[]) {
  // convert index to 8-byte-array in little-endian
  uint8_t bytes_index[8];
  // TODO: hardware optimization
  bytes_index[0] = index >> 8 * 0;
  bytes_index[1] = index >> 8 * 1;
  bytes_index[2] = index >> 8 * 2;
  bytes_index[3] = index >> 8 * 3;
  bytes_index[4] = index >> 8 * 4;
  bytes_index[5] = index >> 8 * 5;
  bytes_index[6] = index >> 8 * 6;
  bytes_index[7] = index >> 8 * 7;
  // printf("Index: ");
  // dump_hex(bytes_index, 8);

  // hash index-byte
  byte_t hash_index[32];
  crypto_generichash(hash_index, 32, bytes_index, 8, NULL, 0);
  // printf("hashIndex: ");
  // dump_hex(hash_index, 32);

  // XOR subseed and hashedIndexBytes
  memcpy(subseed, seed, IOTA_SEED_BYTES);
  // TODO: hardware optimization
  for (int i = 0; i < IOTA_SEED_BYTES; i++) {
    subseed[i] = subseed[i] ^ hash_index[i];
  }
  // printf("subseed: ");
  // dump_hex(subseed, IOTA_SEED_BYTES);
}

void address_from_ed25519(byte_t addr_out[], byte_t seed[], uint64_t index) {
  // public key of the seed
  byte_t pub_key[ED_PUBLIC_KEY_BYTES];
  byte_t priv_key[ED_PRIVATE_KEY_BYTES];
  byte_t subseed[IOTA_SEED_BYTES];
  // get subseed from seed
  get_subseed(seed, index, subseed);
  // get ed25519 public and private key from subseed
  crypto_sign_seed_keypair(pub_key, priv_key, subseed);
  // printf("pub: ");
  // dump_hex(pub, ED_PUBLIC_KEY_BYTES);
  // printf("private: ");
  // dump_hex(priv, ED_PRIVATE_KEY_BYTES);

  // digest: blake2b the public key
  byte_t digest[ED_PRIVATE_KEY_BYTES];
  crypto_generichash(digest, ED_PRIVATE_KEY_BYTES, pub_key, ED_PUBLIC_KEY_BYTES, NULL, 0);
  // printf("digest: ");
  // dump_hex(digest, ED_PRIVATE_KEY_BYTES);

  // address[0] = version, address[1:] = digest
  addr_out[0] = ADDRESS_VER_ED25519;
  memcpy((void *)(addr_out + 1), digest, 32);
}

void get_address(byte_t seed[], uint64_t index, address_version_t version, byte_t addr_out[]) {
  if (version == ADDRESS_VER_ED25519) {
    address_from_ed25519(addr_out, seed, index);
  } else {
    // TODO
    printf("TODO");
  }
}

bool address_2_base58(byte_t const address[], char str_buf[]) {
  size_t buf_len = IOTA_ADDRESS_BASE58_LEN;
  return b58enc(str_buf, &buf_len, (const void *)address, IOTA_ADDRESS_BYTES);
  // bool ret = b58enc(str_buf, &buf_len, (const void *)address, IOTA_ADDRESS_BYTES);
  // printf("addr len %ld, %s, ret = %d\n", buf_len, str_buf, ret);
  // return ret;
}

bool address_from_base58(char const base58_str[], byte_t addr[]) {
  size_t addr_len = IOTA_ADDRESS_BYTES;
  return b58tobin((void *)addr, &addr_len, base58_str, strlen(base58_str));
}

// signs the message with privateKey and returns a signature.
void sign_signature(byte_t const seed[], uint64_t index, byte_t const data[], uint64_t data_len, byte_t signature[]) {
  //
  byte_t pub_key[ED_PUBLIC_KEY_BYTES];
  byte_t priv_key[ED_PRIVATE_KEY_BYTES];
  byte_t subseed[IOTA_SEED_BYTES];
  unsigned long long sign_len = 0;
  // get subseed from seed
  get_subseed(seed, index, subseed);
  // get ed25519 public and private key from subseed
  crypto_sign_seed_keypair(pub_key, priv_key, subseed);

  crypto_sign(signature, &sign_len, data, data_len, priv_key);
  // printf("sig len %"PRIu64"\n", sign_len);
  // printf("sig len %lld\n", sign_len);
}

bool sign_verify_signature(byte_t const seed[], uint64_t index, byte_t signature[], byte_t const data[],
                           size_t data_len) {
  byte_t pub_key[ED_PUBLIC_KEY_BYTES];
  byte_t priv_key[ED_PRIVATE_KEY_BYTES];
  byte_t subseed[IOTA_SEED_BYTES];
  byte_t exp_data[200];
  unsigned long long exp_data_len = 0;
  // get subseed from seed
  get_subseed(seed, index, subseed);
  // get ed25519 public and private key from subseed
  crypto_sign_seed_keypair(pub_key, priv_key, subseed);
  if (crypto_sign_open(exp_data, &exp_data_len, signature, ED_SIGNATURE_BYTES + data_len, pub_key) == 0) {
    printf("data size %lld\n", exp_data_len);
    return memcmp(data, exp_data, exp_data_len) ? false : true;
  } else {
    printf("failed\n");
    return false;
  }
}
