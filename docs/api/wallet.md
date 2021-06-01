# Wallet API Reference

This is reference implementation as wallet APIs. Users are able to implement wallet application based on [Client APIs](./client.md#client-api-reference).

## Setting

```{eval-rst}
.. doxygenstruct:: iota_wallet_t
  :members:
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
.. doxygenfunction:: wallet_address_by_index
```

```{eval-rst}
.. doxygenfunction:: wallet_balance_by_address
```

## Balance

```{eval-rst}
.. doxygenfunction:: wallet_balance_by_index
```

## Send

```{eval-rst}
.. doxygenfunction:: wallet_send
```

## Update bech32HRP

```{eval-rst}
.. doxygenfunction:: wallet_update_bech32HRP
```
