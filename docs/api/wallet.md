# Wallet API Reference

The Wallet API provides some helper methods for developers to create wallet alllications.

## Wallet Configuration

```{eval-rst}
.. doxygenstruct:: iota_wallet_t
  :members:
```

## Create and Destory Methods

```{eval-rst}
.. doxygenfunction:: wallet_create
```

```{eval-rst}
.. doxygenfunction:: wallet_destroy
```

```{eval-rst}
.. doxygenfunction:: wallet_set_endpoint
```

```{eval-rst}
.. doxygenfunction:: wallet_update_node_config
```

## Address Methods

```{eval-rst}
.. doxygenfunction:: wallet_ed25519_address_from_index
```

```{eval-rst}
.. doxygenfunction:: wallet_balance_by_address
```

```{eval-rst}
.. doxygenfunction:: wallet_balance_by_bech32
```

## UTXO Methods

```{eval-rst}
.. doxygenfunction:: wallet_send_basic_outputs
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
