# Wallet API Reference

This is reference implementation as wallet APIs. Users are able to implement wallet application based on [Client APIs](./client.md#client-api-reference).

## Setting

```{eval-rst}
.. doxygenstruct:: iota_wallet_t
  :members:
```

```{eval-rst}
.. doxygenfunction:: wallet_update_bech32HRP
```

## Create

```{eval-rst}
.. doxygenfunction:: wallet_create
```

```{eval-rst}
.. doxygenfunction:: wallet_destroy
```

## Endpoint

```{eval-rst}
.. doxygenfunction:: wallet_set_endpoint
```

## Address

```{eval-rst}
.. doxygenfunction:: wallet_address_from_index
```

```{eval-rst}
.. doxygenfunction:: wallet_bech32_from_index
```

## Balance

```{eval-rst}
.. doxygenfunction:: wallet_balance_by_address
```

```{eval-rst}
.. doxygenfunction:: wallet_balance_by_bech32
```

```{eval-rst}
.. doxygenfunction:: wallet_balance_by_index
```

## Send

```{eval-rst}
.. doxygenfunction:: wallet_send
```

## Mnemonic Sentence

```{eval-rst}
.. doxygenenum:: ms_lan_t
```

```{eval-rst}
.. doxygenenum:: ms_entropy_t
```

```{eval-rst}
.. doxygenfunction:: mnemonic_to_seed
```

```{eval-rst}
.. doxygenfunction:: mnemonic_generator
```

```{eval-rst}
.. doxygenfunction:: mnemonic_encode
```

```{eval-rst}
.. doxygenfunction:: mnemonic_decode
```

```{eval-rst}
.. doxygenfunction:: mnemonic_convertor
```

```{eval-rst}
.. doxygenfunction:: mnemonic_validation
```
