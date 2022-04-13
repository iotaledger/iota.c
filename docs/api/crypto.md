# Crypto API Reference

The Cyppto APIs provide an abstraction layer of cryptography functions.

## ED25519 Keypair

```{eval-rst}
.. doxygenstruct:: ed25519_keypair_t
  :members:
```

## Random Bytes

```{eval-rst}
.. doxygenfunction:: iota_crypto_randombytes
```

## ED25519 keypair

```{eval-rst}
.. doxygenfunction:: iota_crypto_keypair
```

## ED25519 Signature

```{eval-rst}
.. doxygenfunction:: iota_crypto_sign
```

```{eval-rst}
.. doxygenfunction:: iota_crypto_sign_open
```

## HMAC-SHA-256

```{eval-rst}
.. doxygenfunction:: iota_crypto_hmacsha256
```

## HMAC-SHA-512

```{eval-rst}
.. doxygenfunction:: iota_crypto_hmacsha512
```

## SHA-256

```{eval-rst}
.. doxygenfunction:: iota_crypto_sha256
```

## SHA-512

```{eval-rst}
.. doxygenfunction:: iota_crypto_sha512
```

## Blake2b

```{eval-rst}
.. doxygenfunction:: iota_blake2b_sum
```

```{eval-rst}
.. doxygenfunction:: iota_blake2b_new_state
```

```{eval-rst}
.. doxygenfunction:: iota_blake2b_free_state
```

```{eval-rst}
.. doxygenfunction:: iota_blake2b_init
```

```{eval-rst}
.. doxygenfunction:: iota_blake2b_update
```

```{eval-rst}
.. doxygenfunction:: iota_blake2b_final
```

## PBKDF2 HMAC

```{eval-rst}
.. doxygenfunction:: iota_crypto_pbkdf2_hmac_sha512
```
